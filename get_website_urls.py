#!/usr/bin/env python
# encoding: utf-8

import sys
from GoogleSearch import google_search
from urlparse import urlparse


def main():
    if len(sys.argv) == 1:
        print 'Usage: %s "search_string"' % sys.argv[0]
        return

    search_string = sys.argv[1]

    links = google_search(search_string)

    if links:
        for link in links:
            o = urlparse(link['url'])
            print o.netloc

if __name__ == "__main__":
    main()
