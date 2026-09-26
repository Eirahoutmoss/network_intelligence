// Command nexus-tray shows Nexus in the Windows notification area:
//
//	Nexus
//	  ● Running
//	  Open Nexus / Start / Stop / Restart / Diagnostics / View logs / Settings / Exit
//
// It runs as the signed-in user without administrator rights. Actions that
// need them (start, stop, restart, logs) ask through the normal Windows
// administrator prompt. Pure Win32 via golang.org/x/sys; no cgo.
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/platform"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClassExW               = user32.NewProc("RegisterClassExW")
	pCreateWindowExW                = user32.NewProc("CreateWindowExW")
	pDefWindowProcW                 = user32.NewProc("DefWindowProcW")
	pGetMessageW                    = user32.NewProc("GetMessageW")
	pTranslateMessage               = user32.NewProc("TranslateMessage")
	pDispatchMessageW               = user32.NewProc("DispatchMessageW")
	pPostQuitMessage                = user32.NewProc("PostQuitMessage")
	pCreatePopupMenu                = user32.NewProc("CreatePopupMenu")
	pAppendMenuW                    = user32.NewProc("AppendMenuW")
	pTrackPopupMenu                 = user32.NewProc("TrackPopupMenu")
	pDestroyMenu                    = user32.NewProc("DestroyMenu")
	pSetForegroundWindow            = user32.NewProc("SetForegroundWindow")
	pGetCursorPos                   = user32.NewProc("GetCursorPos")
	pLoadImageW                     = user32.NewProc("LoadImageW")
	pSetTimer                       = user32.NewProc("SetTimer")
	pPostMessageW                   = user32.NewProc("PostMessageW")
	pRegisterWindowMessageW         = user32.NewProc("RegisterWindowMessageW")
	pSetMenuDefaultItem             = user32.NewProc("SetMenuDefaultItem")
	pGetSystemMetrics               = user32.NewProc("GetSystemMetrics")
	pShellNotifyIconW               = shell32.NewProc("Shell_NotifyIconW")
	pGetModuleHandleW               = kernel32.NewProc("GetModuleHandleW")
	pCreateMutexW                   = kernel32.NewProc("CreateMutexW")
	taskbarCreated          uintptr = 0
)

const (
	wmDestroy    = 0x0002
	wmCommand    = 0x0111
	wmTimer      = 0x0113
	wmApp        = 0x8000
	wmTray       = wmApp + 1
	wmLButtonDbl = 0x0203
	wmRButtonUp  = 0x0205
	wmLButtonUp  = 0x0202
	wmContext    = 0x007B

	nimAdd      = 0
	nimModify   = 1
	nimDelete   = 2
	nimSetVer   = 4
	nifMessage  = 1
	nifIcon     = 2
	nifTip      = 4
	nifShowTip  = 0x80
	notifyVer4  = 4
	mfString    = 0
	mfGrayed    = 1
	mfSeparator = 0x800
	tpmRight    = 0x0008
	tpmBottom   = 0x0020
	tpmRetCmd   = 0x0100
	imageIcon   = 1
	lrShared    = 0x8000
	smCxSmIcon  = 49
	smCySmIcon  = 50
)

const (
	cmdOpen = iota + 1
	cmdStart
	cmdStop
	cmdRestart
	cmdDiagnostics
	cmdLogs
	cmdSettings
	cmdExit
	cmdStatus
)

type wndClassEx struct {
	Size, Style                        uint32
	WndProc                            uintptr
	ClsExtra, WndExtra                 int32
	Instance, Icon, Cursor, Background windows.Handle
	MenuName, ClassName                *uint16
	IconSm                             windows.Handle
}

type msg struct {
	Hwnd    windows.HWND
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

type notifyIconData struct {
	Size             uint32
	Wnd              windows.HWND
	ID               uint32
	Flags            uint32
	CallbackMessage  uint32
	Icon             windows.Handle
	Tip              [128]uint16
	State, StateMask uint32
	Info             [256]uint16
	Version          uint32
	InfoTitle        [64]uint16
	InfoFlags        uint32
	GUID             windows.GUID
	BalloonIcon      windows.Handle
}

type app struct {
	hwnd   windows.HWND
	nid    notifyIconData
	state  string
	status string
}

var a app

func u16(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }

// install locations recorded by the installer
func regValue(name string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Nexus`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue(name)
	return v
}

func nexusURL() string {
	if u := regValue("Url"); u != "" {
		return u
	}
	return "http://localhost:8080/"
}

func nexusExe() string { return filepath.Join(regValue("AppDir"), "nexus.exe") }

func shellExecute(verb, file, params string, show int32) {
	var p *uint16
	if params != "" {
		p = u16(params)
	}
	_ = windows.ShellExecute(0, u16(verb), u16(file), p, nil, show)
}

// refresh updates the tooltip from the service state and the health endpoint.
func refresh() {
	st := platform.ServiceState()
	status := st
	if st == "running" {
		c := &http.Client{Timeout: 2 * time.Second}
		resp, err := c.Get(nexusURL() + "api/health")
		switch {
		case err != nil:
			status = "starting"
		case resp.StatusCode != http.StatusOK:
			status = "degraded"
			resp.Body.Close()
		default:
			resp.Body.Close()
		}
	}
	a.state, a.status = st, status
	label := map[string]string{"running": "Running", "starting": "Starting…", "stopped": "Stopped", "stopping": "Stopping…",
		"degraded": "Running (database unavailable)", "not installed": "Not installed"}[status]
	if label == "" {
		label = status
	}
	setTip("Nexus — " + label)
}

func setTip(s string) {
	u := windows.StringToUTF16(s)
	if len(u) > len(a.nid.Tip) {
		u = append(u[:len(a.nid.Tip)-1], 0)
	}
	copy(a.nid.Tip[:], u)
	a.nid.Flags = nifMessage | nifIcon | nifTip | nifShowTip
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&a.nid)))
}

func addIcon() {
	pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&a.nid)))
	a.nid.Version = notifyVer4
	pShellNotifyIconW.Call(nimSetVer, uintptr(unsafe.Pointer(&a.nid)))
}

func showMenu() {
	m, _, _ := pCreatePopupMenu.Call()
	add := func(flags uintptr, id int, text string) {
		pAppendMenuW.Call(m, flags, uintptr(id), uintptr(unsafe.Pointer(u16(text))))
	}
	dot := map[string]string{"running": "●  Running", "starting": "●  Starting…", "degraded": "●  Running (database unavailable)", "stopped": "○  Stopped", "stopping": "○  Stopping…"}[a.status]
	if dot == "" {
		dot = "○  " + a.status
	}
	add(mfString, cmdOpen, "Open Nexus")
	pSetMenuDefaultItem.Call(m, cmdOpen, 0)
	add(mfString|mfGrayed, cmdStatus, dot)
	add(mfSeparator, 0, "")
	running := a.state == "running" || a.state == "starting"
	if running {
		add(mfString|mfGrayed, cmdStart, "Start")
		add(mfString, cmdStop, "Stop")
	} else {
		add(mfString, cmdStart, "Start")
		add(mfString|mfGrayed, cmdStop, "Stop")
	}
	add(mfString, cmdRestart, "Restart")
	add(mfSeparator, 0, "")
	add(mfString, cmdDiagnostics, "Diagnostics…")
	add(mfString, cmdLogs, "View logs")
	add(mfString, cmdSettings, "Settings")
	add(mfSeparator, 0, "")
	add(mfString, cmdExit, "Exit")
	var pt struct{ X, Y int32 }
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForegroundWindow.Call(uintptr(a.hwnd))
	cmd, _, _ := pTrackPopupMenu.Call(m, tpmRight|tpmBottom|tpmRetCmd, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(a.hwnd), 0)
	pDestroyMenu.Call(m)
	if cmd != 0 {
		pPostMessageW.Call(uintptr(a.hwnd), wmCommand, cmd, 0)
	}
}

func command(id uintptr) {
	switch id {
	case cmdOpen:
		shellExecute("open", nexusURL(), "", windows.SW_SHOWNORMAL)
	case cmdSettings:
		shellExecute("open", nexusURL()+"settings", "", windows.SW_SHOWNORMAL)
	case cmdStart:
		shellExecute("runas", nexusExe(), "service start", windows.SW_HIDE)
	case cmdStop:
		shellExecute("runas", nexusExe(), "service stop", windows.SW_HIDE)
	case cmdRestart:
		shellExecute("runas", nexusExe(), "service restart", windows.SW_HIDE)
	case cmdDiagnostics:
		shellExecute("open", nexusExe(), "diagnostics --gui", windows.SW_SHOWMINNOACTIVE)
	case cmdLogs:
		// The logs are readable by administrators only.
		dir := regValue("DataDir")
		if dir == "" {
			dir = filepath.Join(os.Getenv("ProgramData"), "Nexus")
		}
		shellExecute("runas", filepath.Join(os.Getenv("WINDIR"), "System32", "notepad.exe"), `"`+filepath.Join(dir, "logs", "nexus.log")+`"`, windows.SW_SHOWNORMAL)
	case cmdExit:
		pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&a.nid)))
		pPostQuitMessage.Call(0)
		return
	}
	// reflect state changes soon after start/stop requests
	go func() {
		for i := 0; i < 6; i++ {
			time.Sleep(2 * time.Second)
			pPostMessageW.Call(uintptr(a.hwnd), wmTimer, 1, 0)
		}
	}()
}

// wndProc receives only pointer-sized arguments (syscall.NewCallback requirement).
func wndProc(hwnd, m, wp, lp uintptr) uintptr {
	switch m {
	case wmTray:
		switch uint32(lp) & 0xffff {
		case wmLButtonDbl, wmLButtonUp:
			command(cmdOpen)
		case wmRButtonUp, wmContext:
			refresh()
			showMenu()
		}
		return 0
	case wmCommand:
		command(wp & 0xffff)
		return 0
	case wmTimer:
		refresh()
		return 0
	case wmDestroy:
		pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&a.nid)))
		pPostQuitMessage.Call(0)
		return 0
	}
	if taskbarCreated != 0 && m == taskbarCreated {
		addIcon() // Explorer restarted
		refresh()
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
	return r
}

func main() {
	runtime.LockOSThread()
	// one tray per user session
	h, _, err := pCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(u16(`Local\NexusTray`))))
	if h == 0 || err == windows.ERROR_ALREADY_EXISTS {
		return
	}
	inst, _, _ := pGetModuleHandleW.Call(0)
	cx, _, _ := pGetSystemMetrics.Call(smCxSmIcon)
	cy, _, _ := pGetSystemMetrics.Call(smCySmIcon)
	icon, _, _ := pLoadImageW.Call(inst, 1, imageIcon, cx, cy, lrShared)
	cls := u16("NexusTrayWindow")
	wc := wndClassEx{WndProc: syscall.NewCallback(wndProc), Instance: windows.Handle(inst), ClassName: cls}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		fmt.Fprintln(os.Stderr, "register class:", err)
		os.Exit(1)
	}
	hwnd, _, err := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(u16("Nexus"))), 0, 0, 0, 0, 0, 0, 0, inst, 0)
	if hwnd == 0 {
		fmt.Fprintln(os.Stderr, "create window:", err)
		os.Exit(1)
	}
	a.hwnd = windows.HWND(hwnd)
	taskbarCreated, _, _ = pRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(u16("TaskbarCreated"))))
	a.nid = notifyIconData{Wnd: a.hwnd, ID: 1, Flags: nifMessage | nifIcon | nifTip | nifShowTip, CallbackMessage: wmTray, Icon: windows.Handle(icon)}
	a.nid.Size = uint32(unsafe.Sizeof(a.nid))
	addIcon()
	refresh()
	pSetTimer.Call(hwnd, 1, 10000, 0)
	var m msg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}
