import { expect, test } from '@playwright/test'
import { readFileSync } from 'node:fs'

// First run of a fresh single-host (Windows installer) installation:
// create the administrator in the browser, add the simulated core switch,
// run the health check and export diagnostics and a backup.
// Runs only when FIRST_RUN=1 (the server must have no users yet and
// NEXUS_FIRST_RUN_SETUP=local, NEXUS_SIMULATOR=1).
const USER = process.env.NEXUS_USER ?? 'admin'
const PASS = process.env.NEXUS_PASS ?? 'first-run-admin-pass'

test.skip(!process.env.FIRST_RUN, 'set FIRST_RUN=1 against a fresh installation')

test('first run: create administrator, discover, diagnostics, backup', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByText('Welcome — create the administrator')).toBeVisible()
  await expect(page.getByText('Designed and developed by Hasan Güler')).toBeVisible()
  await page.getByLabel('Administrator username').fill(USER)
  await page.getByRole('textbox', { name: /^Password/ }).fill(PASS)
  await page.getByLabel('Repeat password').fill(PASS)
  await page.getByRole('button', { name: 'Create administrator' }).click()
  await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible()

  // The real Add Device flow against the simulator.
  await page.getByRole('button', { name: 'Add Device' }).first().click()
  await page.getByLabel('IP address').fill('10.20.99.1')
  await page.getByLabel('SNMP username').fill('prometheus')
  await page.getByLabel('SNMP password').fill('nexus-demo-pass')
  await page.getByRole('dialog').getByRole('button', { name: 'Add Device' }).click()
  await expect(page.getByText(/Device ready/)).toBeVisible({ timeout: 120_000 })
  await page.getByRole('button', { name: 'Done' }).click()

  // Settings → Diagnostics & backup
  await page.getByRole('link', { name: 'Settings' }).click()
  await page.getByRole('button', { name: 'Diagnostics & backup' }).click()
  await page.getByRole('button', { name: 'Run health check' }).click()
  const checks = page.getByTestId('health-checks')
  await expect(checks).toContainText('Database')
  await expect(checks).toContainText('Credential encryption')
  await expect(page.getByText(/All checks passed|Passed with warnings/)).toBeVisible()

  const [bundle] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export diagnostic bundle' }).click()])
  expect(bundle.suggestedFilename()).toMatch(/^nexus-diagnostics-.*\.zip$/)
  const zip = readFileSync((await bundle.path())!)
  expect(zip.subarray(0, 2).toString()).toBe('PK')
  // No demo credential in the bundle (zip entries are deflated, so also check the redaction test in Go).
  expect(zip.includes(Buffer.from('nexus-demo-pass'))).toBeFalsy()

  const [backup] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download backup' }).click()])
  expect(backup.suggestedFilename()).toMatch(/\.nxbackup$/)
  await expect(page.getByText('Backup downloaded')).toBeVisible()

  await page.getByRole('button', { name: 'About' }).click()
  await expect(page.getByText('Nexus v1')).toBeVisible()

  // Setup is closed now.
  const st = await (await page.request.get('/api/setup')).json()
  expect(st.required).toBe(false)
})
