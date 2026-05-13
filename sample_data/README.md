# Sample data

Sample collection output for trying ADPathfinder without standing up your own lab.

| File | Source |
| --- | --- |
| `SharpHound.zip` | [BloodHound CE](https://github.com/SpecterOps/BloodHound) |
| `MSSQLHound.zip` | [MSSQLHound](https://github.com/SpecterOps/MSSQLHound) by Chris Thompson |
| `ConfigManBearPig.zip` | [ConfigManBearPig](https://github.com/SpecterOps/ConfigManBearPig) by Chris Thompson |
| `ntds.txt` | NTDS hash dump |
| `hashcat.potfile` | Hashcat potfile |

## Try it

Import the zips into BloodHound CE first (`--setup-bloodhound-api` to configure), then:

    ./adpathfinder.py -i sample_data/SharpHound.zip sample_data/MSSQLHound.zip sample_data/ConfigManBearPig.zip --ad --pwd training --ntds sample_data/ntds.txt -p sample_data/hashcat.potfile

Sample reports in [`../sample_reports/`](../sample_reports/).
