Cachet
------

You probably shouldn't be using this library.

A signed envelope for an opaque array of bytes. 
Data in the cachet is authenticated only, not encrypted.

Cachet library defines:
 - 2 byte static identifier, present on all cachet format versions.
 - 2 byte (u16) indecating the format version number, present on all cachet format versions.
 - one or more cooresponding format versions.

Each cachet format version defines:
 - a byte representation of the format version, intended for serialization/deserialization of the cachet.
 - the exact algorithms & configuration to use for signing for this fomat version.

Algorithms and/or configurations defined in a version must never change, once defined, they are immutable. 
Do NOT expect different versions to use the same algorithms and/or configurations, they exist independent of eachother. 

Serializers should only use the latest format versions.
Deserializers must handle more than one format version.  

No format versions are required to be implemented.


The V1 cachet contains (TODO: move this into src/v1.md):
 - Cachet format version
 - signature of bytes (Ed25519, 32 bytes, verify with last public key in the trust chain that follows)
 - Trust chain for the signautre ( vari, see TC format)
 - length of bytes (u32, 4 bytes)
 - bytes (data, byte-length from previous 4 bytes) 

