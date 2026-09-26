import {
  Box,
  Camera,
  Cloud,
  Cpu,
  HardDrive,
  HelpCircle,
  Laptop,
  Monitor,
  Network,
  Phone,
  Printer,
  Radio,
  Router,
  Server,
  Shield,
  Smartphone,
  Wifi,
  Zap,
  type LucideIcon,
} from 'lucide-react'
import { cn } from './ui'

const ICONS: Record<string, LucideIcon> = {
  router: Router,
  switch: Network,
  firewall: Shield,
  access_point: Wifi,
  wireless_controller: Radio,
  printer: Printer,
  computer: Monitor,
  server: Server,
  phone: Phone,
  camera: Camera,
  storage: HardDrive,
  ups: Zap,
  iot: Cpu,
  virtual_machine: Cloud,
  mobile: Smartphone,
  laptop: Laptop,
  unknown: HelpCircle,
}

export const TYPE_COLORS: Record<string, string> = {
  router: '#7c3aed',
  switch: '#0f766e',
  firewall: '#dc2626',
  access_point: '#0284c7',
  wireless_controller: '#0284c7',
  printer: '#d97706',
  computer: '#475569',
  server: '#4338ca',
  phone: '#059669',
  camera: '#be185d',
  storage: '#4338ca',
  ups: '#ca8a04',
  iot: '#9333ea',
  virtual_machine: '#64748b',
  mobile: '#64748b',
  unknown: '#94a3b8',
}

export function DeviceIcon({ type, className }: { type: string; className?: string }) {
  const Icon = ICONS[type] ?? Box
  return <Icon className={cn('size-4 shrink-0', className)} style={{ color: TYPE_COLORS[type] ?? '#64748b' }} />
}
