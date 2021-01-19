# CreditCardFileScanMinifilter

There are two components:
1. Kernel mode minifilter driver, credfilescan - Driver intercepts PreWrite operations and gets the write buffer. It then forwards that to the user mode component for the analysis. The analysis in this case is to look for the credit card numbers and replace them with specific pattern.
2. User mode console application - This keeps running. Continually looking for the events from the kernel mode driver to scan the buffer for credit card numbers and then replace them with specific pattern. the modified buffer is then passed to driver.

The reason for choosing usermode component is because of rich regex support available in the user mode. Versus kernel mode limited support through API FsRtlIsNameInExpression  https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-_fsrtl_advanced_fcb_header-fsrtlisnameinexpression

How to Run?
1. Install the driver with the help of inf file.
2. Start the driver with sc start credfilescan
3. Start the application CredFileScanUser.exe in the command prompt.

Testing:
Driver and application has been tested in Windows7 environment -
1. Functional testing on small and large files
2. Longevity testing over few hours.
3. Tested the driver with driver verifier for any memory leak or violation.




