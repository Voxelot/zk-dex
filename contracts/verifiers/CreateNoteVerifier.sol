pragma solidity ^0.5.0;

import "./../lib/VerifierBase.sol";

contract Verifier is VerifierBase {
    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.A = Pairing.G2Point([0x2839e77118a1c71f7184ab755cb028709389115bdedb7815e2cf473ff286bc56,0x9dbbdf06e9af3209f37912eb081edf314cb78d4908e7e29c3a9430a3517e70b],[0x271c097f1e6804181fb108aace5b07570b7dc10e65b01949acafc115e70c12e7,0x18a61289e374807ebf80f70508981ae1f52f61962ee40e05ef4747b02d689ae1]);
        vk.B = Pairing.G1Point(0x28ef0ba46c306ede163fde7978d1a79f2f4ca2da598a967a028c603686cdd329,0xb613a3e842aa3fae663cce8ea7b4bb88a836f1e4f40c8384ccf47fd69c0e386);
        vk.C = Pairing.G2Point([0x244d8d7df11c93d2e20a57005d03e889f7496fc24aaa88b102396f19f80d3536,0x2c612aa478561b512bbcfb978de0a3221a383208b98c532f063ed402a718ccb4],[0x1f65a7b35f5977298653ad51542271cda0cb9de7cb1f89ec934c56ac272c9485,0x122e16dc4996d433a3e0239f1b7cd59d1c5545948fd7bb98ca223f1fbd59d6af]);
        vk.gamma = Pairing.G2Point([0x2c2a5829b53a75b8fe44c362d34e3925946be0dadf4c85096ed2f7df9121e1cb,0x196cdf4c8d58609911948edcd67868195a9321142c223472a3ee0b2583530df1],[0x1682e72c29f282a8be49d12a4c6820d47f6e0be5db572d1a4985a14ec5f71204,0x1d3abcaba2be584eaef2c42e6459b220e50d44e6accb017e296ed4f25396bd6f]);
        vk.gammaBeta1 = Pairing.G1Point(0x8c97329221f8b57a2de5284ac2fe57ead70709eb43ef654f949dced38bb5110,0x2e58494277b80793081ad181604ff00401f06930dc81baf6580a05780973818c);
        vk.gammaBeta2 = Pairing.G2Point([0x217a94f2edb1c76d67703dbd169748cbf93ef6b71a53bfc794d01496776e76af,0x325ef84999b8e7262ce328c4e0ef0ab70b5852f429e8a028383841dffcbafc1],[0x2c4f40537a0c4aa6b9fe6aa6c37197f2b22f20a890bb9cb8221f329114c1180d,0x178aa4185ae5fb57036ac9f9e449e6b1b24633d885d9931dbdbb60ff008f51e2]);
        vk.Z = Pairing.G2Point([0x3f471c93f979cba8c4c41113a08f1863b202a3bb4dd68f71d2a8bc603ac2fff,0xda7c4125fb6d02af22b350a4d2e4f53456cbfa849170d67a31b73e1a9e49f16],[0x47d6a8a904c93150158f506061979e9561caca5a2057b93316a0afd0e67e71a,0x2c60e69d802189a5b2c417f6a900d1d4bbdb92e026adac8039e40c828b242f0a]);
        vk.IC = new Pairing.G1Point[](6);
        vk.IC[0] = Pairing.G1Point(0x2a73ed3dd2b3d9ef42192ee9cce806181aad9b758d3baac4b6bd5a808ae64d86,0x3bfcc682b4307564249a46d6dc80fce6f0980ecf3cb5ea8e6bd3cc188b2017b);
        vk.IC[1] = Pairing.G1Point(0x281ab73486ed6227a9bdc4f42cc9a2d188711358ec9bad6e70fd6c75ba261cf5,0x156a4f2881ffd2aa469a2521ffbce2911f0b4874db04ca2c0080f5eded5e0e);
        vk.IC[2] = Pairing.G1Point(0x280323bd870ab7f2e56e940699e770875b17bb5e963b4734e50f90670b9c3a17,0x2a1150d1f98c38e8da5ccef6927311de08f591e2023ea9d2acf2261e69cfed37);
        vk.IC[3] = Pairing.G1Point(0x1d003111cce65478419071ce42ae6e39964c5914b52153b01ad2ce01e39ae6a6,0x18ba694aeaa9d180bc445b115786c0bbe848d00603c35c0987c57e398125def);
        vk.IC[4] = Pairing.G1Point(0x20afb0b1d947d2748bcfd4432025c15d2cc4bc29d7e9439ca16154030e3f5556,0x20148b260da4327d5425618af045466938ad2bfdb65d8222abfa6307ab7691b7);
        vk.IC[5] = Pairing.G1Point(0x13176cc0a3d3b64716ad895b13bc999432413ff65b6f31873c5db2879040f857,0x87de6ffe48d7dd3c1b51f043bacb3535f54d1df73a26f363eeb1f3daf5f52a6);
    }
    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++)
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        vk_x = Pairing.addition(vk_x, vk.IC[0]);
        if (!Pairing.pairingProd2(proof.A, vk.A, Pairing.negate(proof.A_p), Pairing.P2())) return 1;
        if (!Pairing.pairingProd2(vk.B, proof.B, Pairing.negate(proof.B_p), Pairing.P2())) return 2;
        if (!Pairing.pairingProd2(proof.C, vk.C, Pairing.negate(proof.C_p), Pairing.P2())) return 3;
        if (!Pairing.pairingProd3(
            proof.K, vk.gamma,
            Pairing.negate(Pairing.addition(vk_x, Pairing.addition(proof.A, proof.C))), vk.gammaBeta2,
            Pairing.negate(vk.gammaBeta1), proof.B
        )) return 4;
        if (!Pairing.pairingProd3(
                Pairing.addition(vk_x, proof.A), proof.B,
                Pairing.negate(proof.H), vk.Z,
                Pairing.negate(proof.C), Pairing.P2()
        )) return 5;
        return 0;
    }
    event Verified(string s);
    function verifyTx(
        uint[2] memory a,
        uint[2] memory a_p,
        uint[2][2] memory b,
        uint[2] memory b_p,
        uint[2] memory c,
        uint[2] memory c_p,
        uint[2] memory h,
        uint[2] memory k,
        uint[5] memory input
    ) public returns (bool r) {
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.A_p = Pairing.G1Point(a_p[0], a_p[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.B_p = Pairing.G1Point(b_p[0], b_p[1]);
        proof.C = Pairing.G1Point(c[0], c[1]);
        proof.C_p = Pairing.G1Point(c_p[0], c_p[1]);
        proof.H = Pairing.G1Point(h[0], h[1]);
        proof.K = Pairing.G1Point(k[0], k[1]);
        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            emit Verified("Transaction successfully verified.");
            return true;
        } else {
            return false;
        }
    }
}
