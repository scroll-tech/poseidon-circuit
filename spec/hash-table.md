# hash table

Provided by the MPT and codehash circuit and being connected into hash circuit. 

The messages need to be hashed is filled into 2 columns with the hash output and control flags, and can be RLC encoding

| Message Input 1 | Message Input 2 | Hash index     | Control flag |
| --------------- | --------------- | ---------------| ------------ |
| MPT input 1     | MPT input 2     | MPT hash       |      0       |
| bytes in field  | bytes in field  | byte hash      |     2000     |
| bytes in field  | bytes in field  | byte hash      |     1968     |
|      ...        |      ...        |     ...        |     ...      |
| bytes in field  | bytes in field  | byte hash      |      16      |
|                 |                 |                |              |

The `control flag` is 0 for hashing mpt nodes or the length of bytes to be encoded in the following rows. In the codehash scheme each 16 bytes could be put into the same field so it is subtracted by 32 from the previous row until end.