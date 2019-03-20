pragma solidity ^0.5.0;

import "./../lib/VerifierBase.sol";

contract Verifier is VerifierBase {
    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.A = Pairing.G2Point([0x1e05c3383b32b814ed1bfcbabab536c07132a46f42313b5704dbacbe3613aa40,0x226f264e721c47492faf4fed70cb08def754bb8b8d3c22740b52b3f213fabfdc],[0x3edf5294a0174d064e1b490dca3a6c51ad4791af96417ec0baca743b2cd9522,0x2b3f8fb60f7faa9f5edfb51fd067208e4c9bacf55c8bca52f567adc0a2d4fa11]);
        vk.B = Pairing.G1Point(0x5a195b73dd3d6065a7e198ca024e31b4b52599bf94d0ad5e73ed504da23df8c,0x1f3f866d29aa9d347090ecd56538d9943932cdf763033521a17e0abf497649b3);
        vk.C = Pairing.G2Point([0x13e4883d6203ff3b16764a7ccf507612a7d2606da8a73f7378fb7dcc1d4c7901,0x18b9004e9d713a5a492748419795eac8ac878c4f6d682a02d692663667b1501f],[0x1fd353a18b7e7db065aa39dd8b16c51bf483e969a48e4b8b8b4ca3880b788197,0xf90dc537f5e9b19b3a97112826b120de1e901378657b19e47feae4d6c4f331d]);
        vk.gamma = Pairing.G2Point([0x14f006a19127970f5f58cc67badaad3b986838bb7bb957bfe2eb4f5d53a4109d,0x1c33d2c1f231f998528cb23d69cb38d6f1c6d56e27e6d270f70e0653a15b1e7f],[0x1996030116c8667d7b4dd4aa9fa19a80e14e1443a19056d3cb80b1596007039c,0x5cbd906e6f57acc0d652d4b7e70dd7a2eaa2a5186afc118e93cc3a2a2c60a1b]);
        vk.gammaBeta1 = Pairing.G1Point(0x2f0ae45a6c9e7f73a2b2a688e41fcc5a6a7d1c4c1c985efc28d2992fb149fd01,0x1d12667471e9a42e6d2a308e1deca31039edc472cf7c9c3235479a6183e1d33a);
        vk.gammaBeta2 = Pairing.G2Point([0x14a56fc4c752c8665f582f8d6975a2ec287571f70f6a22d773aa4c931d8c3471,0x4982bcb252006d43b14c4a9874e32ce9b54a2081966c6feb1be90610acf7aee],[0x1be235500d3d248d8ab2ffa4abfdf76572c74df5ee4fc731a675e7560a5c47b7,0x24209451a0ccb9d06a5597262267f46d3a6013f20abfdb26d1542218ecb35531]);
        vk.Z = Pairing.G2Point([0x780183e728771ebc1db5f188cf8cfa3d2b48d3301040f6eb0a8b12e230bdae6,0x2ed9b224ab5e68052fa278c30ab76d0f80102413122ce9ca57bded0fb42feddb],[0x2a1ef0410ba15abaf4a423ed91a119fb6ee54107b590d65d8ee391dd7457d9eb,0x167138e711e9385c70d5564af73e8a4b65381b364a24fc4a19ef6684755f5bb4]);
        vk.IC = new Pairing.G1Point[](8);
        vk.IC[0] = Pairing.G1Point(0x25f7aa0348da077dacdde59abcf5c1d8573ae0f52d62ac8ac6dd09eaddda2509,0x197c74a819a476fdc6b14d02e5aace1a2d07267b6e6bcfecf142503f5566d1b1);
        vk.IC[1] = Pairing.G1Point(0x2a17be685cd3948504d38327ca1257966adaace1aa53d3c8a8be8d00519db1ce,0x1f634ee7045262776c214860edf3dfb1625bd89de81d804312b19c52ef17bf2f);
        vk.IC[2] = Pairing.G1Point(0xb1b201ff2245c2b86cb37591bc220ef33f4b8b95613a85054d556227e00892a,0x12d01f6acebb494b12b4a7bc7c0c3092c73de878699fad36e3970c790cb57364);
        vk.IC[3] = Pairing.G1Point(0x205d605ff08b6be98963e8b6995cea7b0abee35ce4b380ef5d02fd0e16e42fca,0x20bbd3d490d83def52e0b14ed2357246295e0559901911f8073a2f30547c021f);
        vk.IC[4] = Pairing.G1Point(0x27456fbd94381f93a86fe1c9fbe7e38a1f3d87be095151f868d7802b0cdd15ed,0x143f7b9af9291c97482e93613fd5f4ce1f208016d6fe0eae74e84ce4deb3baaf);
        vk.IC[5] = Pairing.G1Point(0x302d75004a806e55a6c4ae0fc7201608867ffd65dc5e43840b77858f40cd38a3,0x3c0cb19660d6123ac98d264b14a54df19b771e17bb01a5539df4e2e85747af0);
        vk.IC[6] = Pairing.G1Point(0x11de09c8a42ffea77b29767f1c99ed49c316addb88abc2d88d3a344c9e7b1000,0x1015707954ce659e51dbcb5e2f31d20ad7abca61cf4828110f97f4ca5924e5b5);
        vk.IC[7] = Pairing.G1Point(0x2c3312ecac91642d5fee3ab055b3566c3dc7b6da62dd0edc39232ee214b4fd1f,0x1eb26ba20f47df393017399f697681cbbb178b8f65ceded2af220ca5b5e6216d);
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
        uint[7] memory input
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
