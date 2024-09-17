# wr
## ffuf wrapper for some additional logic and convenience


wr works as a `wrapper` around ffuf and it's implementing the following:
  * Easier implementation for the default scan on ffuf for batch processing (I'm really bored typing /FUZZ each time)
  * Adding a quick check on robots.txt to include keywords on the initial list
  * Add subdomain/domain as keywords always to the wordlist, adding variations of them as .zip, .tar.gz, .7z
  * Perform a 'quick' scan initially with a small list ( I'm using the list from dirsearch, but you can use any )
  * Wait for 5 seconds with the option to cancel the next scan or,
  * Perform a 'long' scan by deduplicating the entries that are already scanned and using a larger list for a second pass ( I'm using raft-medium-words-lowercase )
  * Support additional parameters to be passed on demand to ffuf
  * Output findings when present on json format.

Notes: Recursion is also passed with depth 1, to avoid excessive requests. 

*Usage:*
```
wr.py -u https://example.domain.com
wr.py -r urls.txt
```

# parse_ffuf_output.py 
## parser for the json files that are generated from ffuf's json output and the wr process

*Usage:*
```
parse_ffuf_output.py domain.example.com_date.json
parse_ffuf_output.py *.json
```

What is the use for it and why was created?  I need to scan several domains during the day and even though I love dirsearch and the output that is delivering, is often crashing with network timeout, where ffuf is stable, faster, easier on the filtering parameters but I really don't want to add each time FUZZ and reformat URLs just for it, or pass a lenghty path for a list each time. 
