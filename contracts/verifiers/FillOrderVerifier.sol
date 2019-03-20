pragma solidity ^0.5.0;

import "./../lib/VerifierBase.sol";

contract Verifier is VerifierBase {
    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.A = Pairing.G2Point([0x325ccb0fbef8533e91f96636da7764dc95cc6425f62295155f4022cfaeb4dcb,0x91794b0a534af247e7c97c2f59bfcbd391dbaeb7daffab4c3a40d0e649c05c],[0xb30ff77614b130326fc0648be21a69584cd1887801513705cb586b655405257,0xcda775e1231093ab990fb2f3b584c855e0e204b34030920e42b2ded97f338d3]);
        vk.B = Pairing.G1Point(0x2c8d82eff09a6a4c4961c0213c32abedb38cbf9af146c06ed70715494fd18827,0x1afbcbae3c9c3f02edf63ce3861113db500211bc79dbcb392cad66d9080b5676);
        vk.C = Pairing.G2Point([0xf6e7787e2eaf6ebd5f8e3b8be12cf1311fc0950178aab4e06f357b821951ded,0xf6127ee966a6b134e244d092d9f94a37d97e8ff89c2a6a107cfde43ee0adaf4],[0x2f0f8b156d9933fcc8fe9fa07bdcbc7800cfc3767a197eed567c50c618c791bc,0x28728e382e40af8bf8e56598e9b026445ee4e19f69a1107f41b131fa6da5f34d]);
        vk.gamma = Pairing.G2Point([0x1cd13845dc6d33ca17a8c3390d2e3c03a99361fcaafd061256542330189f4a1b,0x2d6e70d403ef5663d1b8ef28b18945e151b037d34be8396e40eb664982c551b8],[0x6a5e8da3a177e8c6ece5af74b2e393e2d5d9cf5242805888bf78fe5b7fe0be3,0xac7b5b85b6a04df7cdecf3465f7afd77c7ba1027dd81b0968fcf0eb57f3aaba]);
        vk.gammaBeta1 = Pairing.G1Point(0x184141be4d973ecaca0ec6b291eb31729cf7885e358ff340fa431c59a3299141,0x18121c4485246c8c3edfc7dc5b883d29f5eb283a9b0cbf45ef0dec7590b1e4ce);
        vk.gammaBeta2 = Pairing.G2Point([0x1803032898a396467896233f554014ca7e44e629d4cf43d9d47bee02b35f00cb,0x20d8abe9b5767a580ef454654e5598d0727e805a06471a8fe295b91afd50b6c0],[0xbffb39d9aad538d5da7a0159b4a81a79d7106cc06137decf5b138b6bca744a1,0x1d355cedcedb3bdfad99f840cad084c86b0729931121b845c53449dd95935daf]);
        vk.Z = Pairing.G2Point([0x13754b19d4842321b51ad934d52f937fd23ff3130d9204464e08fa09d74cbb16,0xe447775e48a2672b7ac93d3d65c3f10ecb2721c3a6ffef680da16611b2044d3],[0x3efa22e3564e5eb0021c04a903ff133d6dae1986bb8099dbd1953665b9da5a1,0x1748b09b5c469cd8dd197fe2189f71c9ef8a5f8234226dea91ddb09aa72ecdbf]);
        vk.IC = new Pairing.G1Point[](8);
        vk.IC[0] = Pairing.G1Point(0xfcf2c038eb70c8bc8d2e2af804022134c3819dc797521f7bdde8b7bb2acfe86,0xbbcb7504b8de815842c5826fbf2518b27e6511281c14ede744ec4fa05d8b2d3);
        vk.IC[1] = Pairing.G1Point(0x246ee6c90a7a0f3a7a5875ac4dc694209f67f79faecf8c2ce2112d3a88ae7184,0x22009b7d727db9b0bc54534a633c4269b78a44d3946eefc289f9b646aae87dae);
        vk.IC[2] = Pairing.G1Point(0x93e3b5da63f2366afeacbeb9f86b6953212eb93ca065009fa09eb2b4e2968f3,0x23f5d9fa4f25efe8bedf74ac185be4b383ac693f7b3510561d20311e797c7646);
        vk.IC[3] = Pairing.G1Point(0x1d49895823d84971bea0d12b60f0d07bb506716835abad579551657928020263,0x2228bc067c946146aeeb46814e058aa0782b2819d8b8b98705f940bcee532123);
        vk.IC[4] = Pairing.G1Point(0x3f158cfc5cb61e7c1201bcaea656e0db6a091978e32341430546f975e330c72,0x183af22776c00010c26828c5fc70acc9cb9c894d271d9443147de7de62206a68);
        vk.IC[5] = Pairing.G1Point(0x28b837d25bfdeb3626a5903c82cab6e9c157ba19f3770aaf45a41b281ee5580f,0xcb537f8cae7a983a62d9a50848f49e80e5b19d50b0a16e6a7818acdcb5aba8);
        vk.IC[6] = Pairing.G1Point(0x4b5befb4ad17feff42aca149d779ddb26d48b74356d865faa6309774a09cf05,0x150b63d512c248e9f857eb0546cbe0ee565c876ea2ee1366902ba2cec70b8cc2);
        vk.IC[7] = Pairing.G1Point(0x10667e4981f8e4dfe1bfa0e0f657897abc51a6f05f35d001666750b33112b6,0x2793e1a5d7f105215e11126461d3fc68d21bb21faa10318f3ea0d015fe1182ab);
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
