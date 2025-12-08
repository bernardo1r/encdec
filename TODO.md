### TODO

- [x] Remove completely '--stdin' feature, leaving for the program to choose whether received a filename or from stdin
- [x] Check stdin and stdout before asking for password
- [x] Refactor error handling insinde defer with errors.Join
- [ ] Refactor read password function out of crypto.go file (?)
- [ ] Check errors.Join behavior with fmt.ErrorF after
- [x] Remove debug prints
- [ ] Better error messages(?), perhaps with more error variables (?)
