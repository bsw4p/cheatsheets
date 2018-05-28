# Bash<=> Powershell



| Bash                                        | Powershell                                                 |
| ------------------------------------------- | ---------------------------------------------------------- |
| ```find . -name *.txt```                    | ```  Get-ChildItem -Recurse -Force -Include *.txt -Name``` |
| ```grep -r "blah" *```                      | ```dir * -rec | Select-String <pattern>```                 |
| ```for i in *; do echo $i; done```          | ```Get-ChildItem | ForEach-Object { echo $_.Name  }```     |
| ```for i in `seq 0 10`; do echo $i; done``` | ```for ($i=0; $i -le 10; $i++) { $i }```                   |
| ```man```                                   | ```help```                                                 |
| ```alias grep=grep```                       | ```   New-Alias -Name blah -Description blah echo blah ``` |

