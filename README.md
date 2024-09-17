# wr
## ffuf wrapper for some additional logic and convenience


wr works as a `wrapper` around ffuf and it's implementing the following:
  * Easier implementation for the default scan on ffuf for batch processing (I'm really bored typing /FUZZ each time)
  * Adding a quick check on robots.txt to include keywords on the initial list
  * Add subdomain/domain as keywords always to the wordlist
  * Perform a 'quick' scan initially with a small list ( I'm using the list from dirsearch, but you can use any )
  * Wait for 5 seconds with the option to cancel the next scan or,
  * Perform a 'long' scan by deduplicating the entries that are already scanned and using a larger list for a second pass ( I'm using raft-medium-words-lowercase )
  * Output findings when present on json format.

Notes: Recursion is also passed with depth 1, to avoid excessive requests. 
