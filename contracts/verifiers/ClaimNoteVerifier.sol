pragma solidity ^0.5.0;

import "./../lib/VerifierBase.sol";

contract Verifier is VerifierBase {
    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.A = Pairing.G2Point([0x19e5af8682711c32ca3ba641cf7af005d2f8c6ce3db6709a27a1ce3d0aaf0792,0x1cbd38b29b3e1e31cffeb9035426d2443a22d1f3e4af5fe887f8753882075988],[0x29c84a3be2a90b7cb9347c34105a556f0d5bc2b82064bd30449abcd91e8dcab6,0x2098237d070c0e615991358b1e8a1507d1b0ec4a7e0534b51acc255c9722d4]);
        vk.B = Pairing.G1Point(0x140babf6e1158513b5abcd8777927c9dbaf01807a11c384332a295c19fa9307,0x9959189b5c4b802714484b163ee143db49f9a749ce562d9d723e9da28bd49f0);
        vk.C = Pairing.G2Point([0x285404833e2c99a3945f31cd5241d2afe2121d7faf61b540e357ec034a5f6225,0x2409293c2ba9f41cc68bc2a81cac37d4eae3ccf79a18fe9c144b908504565437],[0x184ef3848f22e1eaf0dfad0d8f13d734eb0cd5402cac72fee8303b108b789652,0x1446f14b42dac6c46947cdd99b3ee1082dab137991cf466929abc9e079fce11]);
        vk.gamma = Pairing.G2Point([0x15c5785d88efaa08f961282a57e37507690044b09c3786901cf6d97b075b871e,0xb25410a0c0862f550820a03ced5f758cb7174ea3c7831b597eedb55cdc21c5d],[0xbb2761d75b7a81af48fbee83499a47bc853158a91d29af1bc39a00ba1258c67,0xf8ef3eef9d7430bd5ad372ba00439b700cc173b96aa6e917b8b09622d92ac0]);
        vk.gammaBeta1 = Pairing.G1Point(0x112585c85e87e98ceb5a89b61c0c0ceff9c33d0a888ba6034719c8236f5dcc48,0x14293c8d40c702c87681c477c0bb97176c5e3e217fc8b4db035ed6fef759d2a9);
        vk.gammaBeta2 = Pairing.G2Point([0x260ee03c690589325c4ab5e26f08390fe2cf3de330d8a9f7325e2db5962e0def,0x222e0214fb2d03857c524b47d5d0a05bf8be995927e19b0156ec88a60592c8a8],[0x8a3e12c2ace381d1fa06e74155d5f24b78b1ed39d74ae7f80e1eedadbee513b,0x15ac881b0829b80ba0382e237bd829597295d73d913669a5ea6e9924a0ebf8b4]);
        vk.Z = Pairing.G2Point([0xf2b9cab573b7a27600639689742b813238c3ad13aba98d921aef4bd531d703b,0x3801129591c15f34af1eea0fccceae9c96d9c367e3afdeb96902708dcdc1f0b],[0x28014548f90ff9be6e1d6580a45c0cbb744ab0aa27f7ff788e3af065b98b9018,0xcaa5e94363553a41771b6e39625bf9ce39210fd868d9c3ea173ea0bf225e1b3]);
        vk.IC = new Pairing.G1Point[](6);
        vk.IC[0] = Pairing.G1Point(0x34dbff4837a30370ad9502f8f1f33956855afcb5866f6a41e29da61ab2116ac,0x600682705666fcd35d3da8b35336fb3c5fb09803af53849caf20fbd0436a4c8);
        vk.IC[1] = Pairing.G1Point(0x16262e2e41a9592c26bbbed094d4fa17e70a0a9399b3bed992b5d65d42ac456b,0x2ba3d2dd43772dd47bff99e2876225ab32e4d8b88bb20d670c15f3dd8445829b);
        vk.IC[2] = Pairing.G1Point(0x2565b486edac74048b0526b3abd61ab7bdefd8f7d9b7e47d83451c6ac44108d2,0x12349d4eb6812c3089699994807ee0945cee1718c861f64c58a7a8798f1846c5);
        vk.IC[3] = Pairing.G1Point(0x1d058407deee0341122ae1096cf6c5c92c172dc3f83cc104bf08f41fa558da2e,0x11062379c3fea6d6c191020cb2c6b39de500850d9ff5fc0f1fbd1d38ac0e9bc2);
        vk.IC[4] = Pairing.G1Point(0xcf23c6c5a40460993b8d5a6fe0e94267c3d53f41fe431c2f35d34c7fa4d0c5a,0x2a66f05c802818db6a83505068f36ed5e8fb3aaab72cf1d2b57a09e0d3f0ff53);
        vk.IC[5] = Pairing.G1Point(0x16ce799d0e9a5946a657dcf87aaaf1618c429b6c10786aa1dcc415f84dafc9e6,0x1398fb242083c590c6565658b103b37f86d8995c2808d0fe8758fbfff59ae98b);
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
