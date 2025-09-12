# openidsync

`openidsync` is a PowerShell script for automating the creation of user accounts in an on-premises Active Directory environment based on user data provided in a CSV file. This is useful for synchronizing users from IAM sources (such as Azure Entra ID) to Active Directory.

## What the Script Does

The `newuser.ps1` script:

- Loads user data from a specified CSV file.
- For each user in the CSV:
  - Checks if the user already exists in Active Directory (by `SamAccountName`).
  - If the user does not exist, creates a new AD user account with the provided details (username, password, name, department, OU, and email).
  - If the user already exists, outputs a warning message.

## Usage

1. **Prepare your CSV file**  
   The CSV file should contain the following columns:

   - `firstname`
   - `lastname`
   - `username`
   - `department`
   - `password`
   - `ou` (Distinguished Name of the Organizational Unit)
   - `EmailAddress`

   **Example:**
   ```csv
   "firstname","lastname","username","department","password","ou","EmailAddress"
   "Demo","1","demo1","Demo1","Password123.99","CN=Users,DC=modernworkplace,DC=hu","demo1@modernworkplace.hu"
   ```
