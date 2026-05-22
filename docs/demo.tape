Output docs/images/demo-slideshow.mp4

Set FontSize 18
Set Width 900
Set Height 700
Set Theme "Catppuccin Mocha"
Set Padding 16
Set Margin 0
Set TypingSpeed 35ms

Hide
Type "clear"
Enter
Sleep 200ms
Show

Type "./adpathfinder.py -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd training --ntds training.txt -p hashcat.potfile"
Sleep 700ms
Enter
Sleep 4s

Hide
Sleep 9m
Type "docs/demo_show.sh"
Enter
Sleep 200ms
Wait+Screen@30s /Risk Profile Statistics:/
Show

Sleep 170s
