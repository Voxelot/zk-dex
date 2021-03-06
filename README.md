ZK-DEX *WIP*
=== 

A zero-knowledge decentralized exchange protocol for private ERC-20 token trades. Inspired by ZkDai.

> This is purely for educational purposes and has no warranty of any kind

Setup
---

```bash
npm install
```

Compile ZK-Verifiers
---

```
npm run zokrates-compile
```

TODO
---

- [x] implement zokrates circuits
- [x] zokrates -> solidity tooling
- [x] draft implementation of zk exchange protocol
- [ ] void order api
- [ ] witness generation tooling
- [ ] ZKExchange client web3.js library
- [ ] ZKExchange unit tests
- [ ] UI

Protocol Sequence Diagram
---

```ascii
+-------------+ +-------+ +---------------+ +---------------+ +-----------+ +-------+                +-----------+                          +-----------+ +---------------+ +---------------+ +-------+ +-------------+
| MakerToken  | | Maker | | MakerFillNote | | MakerMintNote | | MakerNote | | Order |                | Exchange  |                          | TakerNote | | TakerMintNote | | TakerFillNote | | Taker | | TakerToken  |
+-------------+ +-------+ +---------------+ +---------------+ +-----------+ +-------+                +-----------+                          +-----------+ +---------------+ +---------------+ +-------+ +-------------+
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            | mintNote MakerMintNote        |               |           |                          |                                      |               |                 |             |            |
       |            |------------------------------------------------------------------------------------->|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       | transfer maker tokens    |                 |               |           |                          |                                      |               |                 |             |            |
       |-------------------------------------------------------------------------------------------------->|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |       register as minted |                                      |               |                 |             |            |
       |            |             |                 |<-----------------------------------------------------|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            | spendNote MakerMintNote (MakerNote + change note)         |                          |                                      |               |                 |             |            |
       |            |------------------------------------------------------------------------------------->|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |        register as spent |                                      |               |                 |             |            |
       |            |             |                 |<-----------------------------------------------------|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |       register anonymously as minted |                                      |               |                 |             |            |
       |            |             |                 |               |<-------------------------------------|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            | createOrder Order(MakerNote + MakerFillNote + hidden taker params)                   |                                      |               |                 |             |            |
       |            |------------------------------------------------------------------------------------->|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |                 register |                                      |               |                 |             |            |
       |            |             |                 |               |           |<-------------------------|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |   make non-transferrable |                                      |               |                 |             |            |
       |            |             |                 |               |<-------------------------------------|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |          mark as pending |                                      |               |                 |             |            |
       |            |             |<-----------------------------------------------------------------------|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            | provide private order details out-of-band (maker token type, maker amount, taker token type, taker amount)                  |               |                 |             |            |
       |            |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------->|            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |        mintNote TakerMintNote |            |
       |            |             |                 |               |           |                          |<-------------------------------------------------------------------------------------|            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |    transfer taker tokens |
       |            |             |                 |               |           |                          |<--------------------------------------------------------------------------------------------------|
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |                          | register as minted                   |               |                 |             |            |
       |            |             |                 |               |           |                          |----------------------------------------------------->|                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      | spend TakerMintNote (TakerNote + change note) |            |
       |            |             |                 |               |           |                          |<-------------------------------------------------------------------------------------|            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |                          | register anonymously as minted       |               |                 |             |            |
       |            |             |                 |               |           |                          |------------------------------------->|               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |            fillOrder (shared order info + TakerNote + MakerFillNote + TakerFillNote) |            |
       |            |             |                 |               |           |                          |<-------------------------------------------------------------------------------------|            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |        register as spent |                                      |               |                 |             |            |
       |            |             |                 |               |<-------------------------------------|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |                          | register as spent                    |               |                 |             |            |
       |            |             |                 |               |           |                          |------------------------------------->|               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |       register as minted |                                      |               |                 |             |            |
       |            |             |<-----------------------------------------------------------------------|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |                          | register as minted                   |               |                 |             |            |
       |            |             |                 |               |           |                          |----------------------------------------------------------------------->|             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            | claimNote (MakerFillNote)     |               |           |                          |                                      |               |                 |             |            |
       |            |------------------------------------------------------------------------------------->|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |    transfer taker tokens |                                      |               |                 |             |            |
       |            |<-------------------------------------------------------------------------------------|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |            mark as spent |                                      |               |                 |             |            |
       |            |             |<-----------------------------------------------------------------------|                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |                          |                                      |               |     claimNote (TakerFillNote) |            |
       |            |             |                 |               |           |                          |<-------------------------------------------------------------------------------------|            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |                          | transfer maker tokens                |               |                 |             |            |
       |            |             |                 |               |           |                          |------------------------------------------------------------------------------------->|            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
       |            |             |                 |               |           |                          | mark as spent                        |               |                 |             |            |
       |            |             |                 |               |           |                          |----------------------------------------------------------------------->|             |            |
       |            |             |                 |               |           |                          |                                      |               |                 |             |            |
```