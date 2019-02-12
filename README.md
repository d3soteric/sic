# Sharing is Caring
SiC is a script to help authorized security professionals find overshared files in a simple, yet powerful location: their organizations Microsoft Office365 OneDrive “Shared with Everyone" folder.   It was being released in tandem with a SANS reading room gold paper (link forthcoming).

There is no vulnerability being exploited in Microsofts services, and requests are similar to those that would be sent if accessing the resources via a web browser.

The script sends a series of web requests to authenticate as a domain user against office365 (login.microsoftonline.com).  (The authentication process is done once per execution of the script regardless of how many users’ to be checked).

The script then checks against the user-provided list of usernames (username only, no domain) to see if any of the users have files in their shared with everyone folder that the authenticated user can view.

A list of filenames and links to each file is returned for further analysis.

```
Usage: sic.ps1 <inputFile> <outputFile> 
[-proxy][-proxy options]
```

## To-dos
- [ ] Support for accounts without TFA enabled and those with TOTP enabled (currently only SMS will work)
- [ ] output is kind of limited right now (txt file) csv or sqlite or something would be better
- [ ] A lot of text is output to the screen, that can be annoying
- [ ] Support for searching other folders besides “Shared with Everyone”
- [ ] Cleanup since this is how I learned  PowerShell so messiness in the code is going to be there

## License
Copyright (C) 2018 Dennis Taggart, all rights reserved.   
This program is distributed in the hope that it will be useful, but without any warranty;    
without even the implied warranty of merchantability or fitness for any purpose.   
The author of this code accepts no liability or responsibility for how you use this code or the knowledge you gain from it.  It is intended for authorized use only.  
Make sure you have permission before using it. 
