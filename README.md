# yara-rules
Yara rules for detecting interesting or malicious network traffic.

## Testing

Yara rules can be tested against fresh [MalwareBazaar](https://bazaar.abuse.ch/) samples in an easy-to-use online GUI called the [Yara Scan Service](https://riskmitigation.ch/yara-scan/), ensuring that the rule flags malicious traffic as expected. This won't ensure that your rule doesn't trigger on normal traffic, but it will help ensure that it does on malicious traffic.

### Pull Logs

To pull Nginx logs from a remove server to conduct manual analysis to develop rules locally, use the following command:

```bash
# Pull logs from remote server
$ scp -r user@machinename:/var/log/nginx/*.gz ./yara-rules/samples
# Delete logs from remote server
$ ssh user@machinename "sudo rm /var/log/nginx/*.gz"
# Unzip logs
$ gunzip ./yara-rules/samples/*.gz
```
