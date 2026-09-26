import { expect, test, type Page } from '@playwright/test'

// End-to-end MVP scenario against a server running in demo mode
// (NEXUS_SIMULATOR=1) with a fresh database.
const USER = process.env.NEXUS_USER ?? 'admin'
const PASS = process.env.NEXUS_PASS ?? 'admin-pass-123'
const SHOTS = process.env.SHOTS_DIR

async function shot(page: Page, name: string) {
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: false })
}

test.describe.configure({ mode: 'serial' })

test('MVP: add device, discover, ask, explore topology, open CLI', async ({ page }) => {
  await page.goto('/')
  await page.getByLabel('Username').fill(USER)
  await page.getByLabel('Password').fill(PASS)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible()

  // Add Device: IP + SNMP username + password only.
  await page.getByRole('button', { name: 'Add Device' }).first().click()
  await page.getByLabel('IP address').fill('10.20.99.1')
  await page.getByLabel('SNMP username').fill('prometheus')
  await page.getByLabel('SNMP password').fill('nexus-demo-pass')
  await shot(page, '01-add-device')
  await page.getByRole('dialog').getByRole('button', { name: 'Add Device' }).click()
  await expect(page.getByText('SNMP authenticated').first()).toBeVisible()
  await expect(page.getByText('Huawei detected').first()).toBeVisible()
  await expect(page.getByText(/Device ready/)).toBeVisible({ timeout: 90_000 })
  await expect(page.getByText('Topology updated')).toBeVisible()
  await shot(page, '02-discovery-done')
  await page.getByRole('button', { name: 'Done' }).click()

  // Dashboard reflects the network.
  await page.getByRole('link', { name: 'Dashboard' }).click()
  await expect(page.getByText('Network devices')).toBeVisible()
  await shot(page, '03-dashboard')

  // Explorer questions from the product brief.
  await page.getByRole('link', { name: 'Explore Network' }).click()
  const ask = async (q: string) => {
    await page.getByPlaceholder(/Laboratuvarda/).fill(q)
    await page.getByRole('button', { name: 'Ask' }).click()
  }
  await ask('Kaç switch var?')
  await expect(page.getByText('Toplam 6 switch var.')).toBeVisible()
  await ask('HP yazıcıları göster')
  await expect(page.getByText(/2 .*yazıcı bulundu/)).toBeVisible()
  await ask('Laboratuvarda Windows XP kullanan cihazları göster')
  await expect(page.getByText(/konum tanımlı değil/)).toBeVisible()
  await ask("SW-CORE-01'e bağlı cihazları göster")
  await expect(page.getByText('SW-CORE-01 cihazına doğrudan bağlı 3 cihaz var.')).toBeVisible()
  await shot(page, '04-explore-connected')

  // Import locations from SNMP sysLocation, then the lab question works.
  await page.getByRole('link', { name: 'Locations' }).click()
  await page.getByRole('button', { name: 'Import from SNMP location' }).click()
  await expect(page.getByText(/placed 6 network devices/)).toBeVisible()
  await page.getByRole('link', { name: 'Explore Network' }).click()
  await ask('Laboratuvarda Windows XP kullanan cihazları göster')
  await expect(page.getByText(/4 cihaz \(windows xp\) bulundu/)).toBeVisible()
  await shot(page, '05-explore-xp')

  // Topology renders nodes.
  await page.getByRole('link', { name: 'Topology' }).click()
  await expect(page.locator('.react-flow__node').first()).toBeVisible()
  expect(await page.locator('.react-flow__node').count()).toBeGreaterThan(30)
  await page.getByLabel('Network devices only').check()
  await expect.poll(async () => page.locator('.react-flow__node').count()).toBeLessThan(10)
  await shot(page, '06-topology')

  // Device detail with evidence, then CLI drawer.
  await page.getByRole('link', { name: 'Devices', exact: true }).click()
  await page.getByPlaceholder(/Search name/).fill('SW-CORE-01')
  await page.getByRole('link', { name: /SW-CORE-01/ }).first().click()
  await expect(page.getByText('Why Nexus thinks this is…')).toBeVisible()
  await shot(page, '07-device')
  await page.getByRole('button', { name: /Interfaces/ }).click()
  await expect(page.getByText('XGigabitEthernet0/0/1').first()).toBeVisible()
  await page.getByRole('button', { name: 'Open CLI' }).click()
  await expect(page.getByText('connected', { exact: true })).toBeVisible()
  await page.locator('.xterm-helper-textarea').pressSequentially('display version\r')
  await expect(page.locator('.xterm-rows')).toContainText('V200R021C00SPC100')
  await shot(page, '08-cli')

  // A printer's evidence explains the classification.
  await page.goto('/devices/printers')
  await expect(page.getByText(/5 devices/)).toBeVisible()
  await page.getByRole('link', { name: /f1-prn-hp-01/i }).click()
  await expect(page.getByText('Printer-MIB answered')).toBeVisible()
  await shot(page, '09-printer-evidence')
})
