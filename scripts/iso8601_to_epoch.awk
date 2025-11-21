#!/usr/bin/awk -f
# Converts ISO 8601 timestamp to Unix epoch time
# Works with GNU Awk (gawk)

BEGIN { FS = "[-T:Z]"; }
{
  # Assumes input format is YYYY-MM-DDTHH:MM:SSZ
  # mktime() is a gawk extension
  print mktime($1 " " $2 " " $3 " " $4 " " $5 " " $6);
}
