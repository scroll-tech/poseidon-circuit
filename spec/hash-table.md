## External Table

The hash circuit exposes a table containing multiple inputs/output pairs. This table can be looked up by the MPT and codehash circuits. The table has four columns: 2 inputs, 1 digest output, and 1 for control flags.

| 0: Hash index   | 1: Message       | 2: Message      | 3: Control flag |
| --------------- | ---------------- | --------------- | --------------- |
| MPT digest      | MPT input 1      | MPT input 2     |      0          |
|                 |                  |                 |                 |
| var-len digest  | word 0           | word 1          |     2000        |
| var-len digest  | word 2           | word 3          |     1968        |
|      ...        |      ...         |     ...         |     ...         |
| var-len digest  | word W-2         | word W-1        |      16         |
|                 |                  |                 |                 |


The hash circuit supports two modes:

### MPT Mode

Compute the digest of two message words, as in Merkle trees. This type of entries is indentified by the control flag value of 0.

### Var-Len Mode

Compute the digest of a variable-length message. One such entry is composed of consecutive rows with the same digest value, and where the control flag is not 0.

The message is chunked into `W` words of `STEP/2` bytes packed into field elements. The words are given two-by-two on consecutive rows in the table, absorbing `STEP` bytes per row. The control flag on a given row indicates the number of message bytes remaining in the current and following rows. On the last row, `control <= STEP`.


## Internal Table (hash_table_aux)

| Row      | 0: State (capacity) | 1: State (rate) | 2: State (rate) | 3: State-for-next | 4: State-for-next | 5: Hash Out |
| -------- | ------------------- | --------------- | --------------- | ----------------- | ----------------- | ----------- |
| previous |                     |                 |                 |                   |                   |             |
| current  |                     |                 |                 |                   |                   |             |

