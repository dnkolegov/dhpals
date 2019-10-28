# Attacks on Diffie-Hellman Protocols

This paper contains high-level instructions to perform practical labs within the workshop.
Some tasks were taken from the Cryptopals challenges, some tasks are original.

## Labs

### Basic Diffie-Hellman Protocol
Implement the `GenerateKey` and `DH` methods of `dhgroup` interface on `GroupParams` type. 

Run `TestDH` to be sure your implementation is correct:

```
go test ./dhgroup -run TestDH
```

### Small-subgroup Attack

Realize `newDHOracle` function in `oracle.go` and its API.
Then read [the description](docs/small_subgroup_attack.txt) of the Small-subgroup attack.

To perform the attack implement `runDHSmallSubgroupAttack` function and run the `TestSmalSubgroupAttack` test:

```
go test -run TestSmallSubgroupAttack
```

###  Small-subgroup and Pollard's Kangaroo Attacks

Implement the `catchKangaroo` function following [the instructions](`docs/kangaroo_attack`).
To verify the implementation of the Pollard's algorithm run the `TestKangarooAlgorithm` test:

```
go test -run TestKangarooAlgorithm
```

Then develop `runDHKangarooAttack` and verify the results:

```
go test -run TestKangarooAttack
```

P.S. It may take several minutes to complete the attack.

#### Additional task (optional):

Add protection against the small-subgroup attack into `DH` method. 
Run the tests and make sure that the attacks above do not work anymore.

### Elliptic Curve Cryptography

Implement the `Curve` interface defined in `elliptic/elliptic.go`. 

You may use instructions from the `docs/elliptic_curves` or any other mathematical papers.

`elliptic_test` contains multiple tests for different real and custom curves. 
The real test vectors of P-256 and P-224 curves are used to verify the correctness of multiplication operation.

It should be noted, that the elliptic curve design follows the [Golang's approach](https://golang.org/src/crypto/elliptic/elliptic.go). 
It is highly recommended to employ that as a reference code.

### Elliptic-curve Diffie Hellman Protocol
Now implement `GenerateKey` function and use it to implement elliptic-curve Diffie-Hellman protocol. 

Run `TestECDH` to verify your function:

```
go test ./elliptic -run TestECDH
```

### Invalid Curve Attack
Review the ECDH oracle located in the `oracle.go` and its API.

Read the description of the [Invalid curve attack](docs/elliptic_curves.txt).

Implement `runECDHInvalidCurveAttack` function and run `TestECDHInvalidCurveAttack`:

```
go test -run TestECDHInvalidCurveAttack
```

### Insecure Twist Attack

Implement the single-coordinate Montgomery's ladder using the instructions from the
 `docs/twist_attack`.

Verify the implementation running the following tests:

```
go test ./x128
go test -run TestCurvesP128AndX128
```

Review the x128 oracle located in the `oracle.go` and its API.

Implement Pollard's Kangaroo algorithm for elliptic curves and make sure it works properly:

```
go test -run TestECKangarooAlgorithm
```

Now, you have got all necessary primitives to implement the attack against the twist.

Implement `runECDHTwistAttack` function and verify the solution:

```
go test -run TestTwistAttack
```

#### Caveats
The attack may take 10-15 minutes.

The original challenge has the following HINT:
 ```
 You may come to notice that ku = -ku, resulting in a combinatorial explosion of potential CRT
 outputs. Try sending extra queries to narrow the range of possibilities.
```

To simplify your life, let's imagine that the ECDH implementation has another vulnerability which
allows you to learn some bits of information.
This vulnerable feature accessible via `privateKeyOracle` function.
So, it allows you to filter incorrect points. If you think it was cheating
you may don't use this method and check all combinations using more sophisticated methods.

### Key-compromise Impersonation

Read [Tox Handshake Vulnerable to KCI](https://github.com/TokTok/c-toxcore/issues/426) and try to understand
the security model of the KCI.

The task suggests that you have compromised Bob's server and got the private key.
The aim of the task is to impersonate Alice. You need to send a message to Bob.
Bob will think the he will received the message from Alice, but he actually  will received the message from Mallory.

Implement `runKCIAttack` function and verify the solution:

```
go test -run TestKCIAttack
```

## References
1. [J.M. Pollard. Monte Carlo Methods for Index Computation](https://www.ams.org/journals/mcom/1978-32-143/S0025-5718-1978-0491431-9/S0025-5718-1978-0491431-9.pdf)
2. [Nigel Smart. Introduction to ECC](https://cyber.biu.ac.il/wp-content/uploads/2017/01/NigelSmart-BIU2013-2-3.pdf)
