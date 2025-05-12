# dlpa-SensitiveDataEntropyAnalyzer
Calculates the entropy of files and directories to identify potential sensitive data based on high randomness and structured formats, bypassing reliance on predefined keywords or patterns. Flags files exceeding an entropy threshold for further investigation. - Focused on Tools for assessing the effectiveness of data leakage prevention (DLP) measures. This involves generating realistic but fake sensitive data (e.g., credit card numbers, names, addresses) using Faker and then testing how well DLP systems detect and prevent the exfiltration of this data. Focus on validating DLP rules rather than building a full DLP system.

## Install
`git clone https://github.com/ShadowStrikeHQ/dlpa-sensitivedataentropyanalyzer`

## Usage
`./dlpa-sensitivedataentropyanalyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-t`: Entropy threshold. Files exceeding this value will be flagged. Default: 4.5
- `-r`: Recursively analyze directories.
- `-v`: No description provided
- `-g`: Generate fake sensitive data for DLP testing.
- `-n`: Number of files to generate when using -g. Default: 10
- `-d`: Output directory for generated files. Default: fake_data

## License
Copyright (c) ShadowStrikeHQ
