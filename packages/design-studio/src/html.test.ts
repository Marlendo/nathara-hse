import { describe, expect, it } from 'vitest'
import { valueForField } from './html'

const credential = {
  tenantName: 'Nathara HSE',
  recipientFullName: 'Avery Chen',
  credentialName: 'Confined Space Entry and Monitor',
  credentialCode: 'CSE-201',
}

describe('credential data fields', () => {
  it("prints the training record's details, blank when there are none", () => {
    expect(
      valueForField('record.details', {
        ...credential,
        recordDetails: 'Level 2 entrant and attendant',
      }),
    ).toBe('Level 2 entrant and attendant')
    expect(valueForField('record.details', credential)).toBe('')
  })
})
