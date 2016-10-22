# Time stopping results for the Static Analyzer
* Samples have been selected from known `malware` samples (see internal `malware` repository) using the `random-samples](./random-samples) script.
* Number of uploaded samples: `10000`
* Number of samples successfully analyzed: `9265`
	* Note that the reason for most failures has been the sample size filter (>10 MB). See [fails.txt](./fails.txt) for the remaining reasons/bugs.
* The [time](./time) script provides the following information (Note that all `ENABLE_*` settings have been set to `FALSE` beforehand):
	* Total time taken to analyze all `9265` samples was `65441` seconds or about `18` hours
	* Average time needed for one sample is about `7` seconds
	* The fastest analysis has been `1/5th` of a second
	* The slowest analysis has been `626` seconds or about `10 1/2` minutes
	* Note that the fastest and slowest analysis have been outliers, see [analysis.txt](./analysis.txt) for a complete list of the sample results

`time` output:
```bash
$ ./time
Seconds taken for 9265 samples: 65441.610474586967
Average per sample is (in seconds): 7.06331
5B05609B32832C76A3C7D1BCFF28631DF0281ABCB5479885D29BBD5FAE4A772D  |  1477075288.0   |  1477075288.22  |  0.213479042053
A96F6FAE3F1580349C955F565039AE99DED09C1D282F4A09974EA813E88F8475  |  1477100171.31  |  1477100797.35  |  626.03972888
```

* [sorted_analysis.txt](./sorted_analysis.txt) contains the content of [analysis.txt](./analysis.txt), sorted by the analysis time (generated using `LC_ALL=C sort -gk7 analysis.txt  | column -t > sorted_analysis.txt`)
