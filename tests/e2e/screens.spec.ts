import { test, type Page } from '@playwright/test'

// Captures screenshots of the main pages (documentation / visual review).
// Runs only when SHOTS_DIR is set and after mvp.spec.ts populated the demo.
const SHOTS = process.env.SHOTS_DIR
test.skip(!SHOTS, 'SHOTS_DIR not set')

async function login(page: Page) {
  await page.goto('/')
  await page.getByLabel('Username').fill(process.env.NEXUS_USER ?? 'admin')
  await page.getByLabel('Password').fill(process.env.NEXUS_PASS ?? 'admin-pass-123')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await page.getByRole('link', { name: 'Dashboard' }).waitFor()
}

test('screens', async ({ page }) => {
  await login(page)
  for (const [path, name, wait] of [
    ['/', 'dash', 'Device types'],
    ['/topology', 'topology-full', ''],
    ['/devices', 'devices', 'Vendor / model'],
    ['/connections', 'connections', 'Device A'],
    ['/locations', 'locations', 'Select a location'],
    ['/reports', 'reports', 'Legacy operating systems'],
    ['/explore?q=Laboratuvarda%20Windows%20XP%20kullanan%20cihazlar%C4%B1%20g%C3%B6ster', 'explore-xp', 'bulundu'],
  ] as const) {
    await page.goto(path)
    if (wait) await page.getByText(wait).first().waitFor()
    else await page.waitForTimeout(1500)
    await page.waitForTimeout(500)
    await page.screenshot({ path: `${SHOTS}/s-${name}.png` })
  }
})
