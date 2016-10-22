# Time stopping results
* Number of uploaded samples: `10000`
* Number of samples successfully analyzed: `9265`
	* Note that the reason for most failures has been the sample size filter (>10 MB). See [fails.txt](./fails.txt) for the remaining reasons/bugs.
* Average time needed for a sample with all `ENABLE_*` settings set to `FALSE` is about `7` seconds as computated using the [time](./time) script:

```bash
$ ./time
Seconds taken for 9265 samples: 65441.610474586967
Average per sample is (in seconds): 7.06331
5B05609B32832C76A3C7D1BCFF28631DF0281ABCB5479885D29BBD5FAE4A772D  |  1477075288.0   |  1477075288.22  |  0.213479042053
A96F6FAE3F1580349C955F565039AE99DED09C1D282F4A09974EA813E88F8475  |  1477100171.31  |  1477100797.35  |  626.03972888
```
