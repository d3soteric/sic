# Sharing is Caring
SiC is a script to help find overshared files in a simple,
yet powerful location in OneDrive: "Shared with Everyone"

The script authenticates as a domain user
then checks against a list to see if any of the
included users have files in their shared with everyone folder
that user can see

A list of filenames is returned for further analysis

`usage sic.ps1 <officeDomain> <orgDomain> <tld> <inputFile>`

## To-do
- [x] GET /common/SAS/EndAuth *to finish auth*
- [x] GET /common/SAS/ProcessAuth 
	- [x] flowtoken
	- [x] ctx(request)
	- [x] hprequestid
- [x] GET/_forms/default.aspx
- [x] GET /layouts/15/authenticate.aspx *for username_org*
- [x] POST /personal/user… *to get the data*