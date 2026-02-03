# Named Data Networking Prefix Table

ndn-pt is a daemon that handles the "prefix table", which is a mapping from name prefixes to the name of its exit router.

eg (from Table 4.3 of publication 1):

Name Prefix | Exit Router
------------|-----------
/alice      | /router5
/bob        | /router5
/cathy      | /router7
/david      | /router6

## Publications

* Patil, Varun. 2025. [Enabling Decentralized Applications: A Transport Perspective](https://escholarship.org/content/qt03r09055/qt03r09055.pdf). Dissertation.
