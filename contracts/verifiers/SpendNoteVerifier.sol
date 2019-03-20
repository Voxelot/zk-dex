pragma solidity ^0.5.0;

import "./../lib/VerifierBase.sol";

contract Verifier is VerifierBase {
    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.A = Pairing.G2Point([0xcaa1bbb6cda93c13a1cb2dd53dccb8494a4a81649835e14cd21aa1f4a0b279a,0x1e03dbfe23021af210471520452cb0f9a061078f626fa7a0970397bb474a5d6],[0x1022afd7ed62af55eeda86f47ffaeba17fdc2ec4e007fb191eacb1b0b94c24d8,0x1d79a77ccb0755bda82c146bf1dd35978af00cd00c9335f3bdd24cc4b6b0e0eb]);
        vk.B = Pairing.G1Point(0x2771a75169395db09eeaef04ef9561162190a487b3926bf3de55215c10b4614b,0x5778fc0e665886a141d5db65ed078138b908ffda1b8e918d1d4a613b311ac55);
        vk.C = Pairing.G2Point([0x119bb2da816566f36b0daca008a6e154539aeedecd9eadddf26d1823e2653eca,0x1ca33cc80706bf5334fc01201d2d16ea238743f6a979370835dbe356d26538b7],[0x2320e39c3e1fca0c57615f905c87bef942678f8ea38b2d0d1b4b229bc168947a,0x20f9c2bac61a0951b1b15a23f6085eca3efcff845d164b5cccbc3d219022e8a5]);
        vk.gamma = Pairing.G2Point([0x2e952afecd98c7d187e4585a41d13a1034df236eb60b803568e9222623293994,0x1a3d9480c1d34f481164f7a9078aa230292036009cbdd2be2edc6d30e2a71005],[0x4383210fac29ad541a38756cb3d164ac77b1c2873bf354d89ee00caa3785793,0x8d38936cbc57a501366e12f1edcee0c9812a74b2b70f47f3c954220194cc83d]);
        vk.gammaBeta1 = Pairing.G1Point(0x13905a4d9137173b4e9167c61dfc87a037d7d6424f3568598670609455f4ab10,0x1852edd1f477ff602deb76dcb65ed50b9aaa2a62e8ebf38a766702e0826b460f);
        vk.gammaBeta2 = Pairing.G2Point([0xced584a875053bdc588c8047bd4b54a55748c043b516aeb61181095eb9f5e47,0xe7598796c5e2ea42b0092e1101b8defd409d9be87348e17898b380736ec5743],[0x742fec2031749e6d9d620020ec3ef51e68ca39ba817786ded2c683bbb9d5be1,0x104199e79cc9ac2b570e73067637678754e516df0f7cd8f74d62fad118183ab8]);
        vk.Z = Pairing.G2Point([0x1cb6d2fd8b2ed1d1b6eccc24be61b892ba1263a091699632faedad38b3b32a52,0xea56e256acda2e61275a0dab01acd64a94bdb7e83fe7988f485c6304f6003ba],[0x2967a85afb2d9b3c91aab3bfbd6af792505597fd6f6341347b38d26f4a98b98b,0x28d9650c5023f254e4d7f2fd4f590967bfb9d9b70a0975aabafa5162a225acb2]);
        vk.IC = new Pairing.G1Point[](8);
        vk.IC[0] = Pairing.G1Point(0x5d026a0c3cf2093a1f7b2127acaa45dbd0c3a0120638ee387fe1feb0aed1586,0xefe2a5b9aa3b2303074b612b2effe3e185e20d55053cf8d0534ac538fc063ac);
        vk.IC[1] = Pairing.G1Point(0x2372785a06644007b4f83bc8d1b18ab9d44aaa7a9c247b1d24796e9050c73635,0x292c4c8594db5a5dbf2af15b40aba6b01b02fb575f7ffe0f6ce409d3d5edd7ca);
        vk.IC[2] = Pairing.G1Point(0x11f583ce2a56bc36f9037b8cd0c00232c52da9d2c53b8b24322fb384a16b6517,0xc48164008c1672df98c5565251bafc34a947359bd444c4138c6173575b6d423);
        vk.IC[3] = Pairing.G1Point(0x21fecf4abc1303a297b00fac3bd7a82aa6acfaa7c690704ff54c66fecd6988b3,0x220feec228b7a73303890897d298d4b380b5a189b88c58c82b88e192ee2ab294);
        vk.IC[4] = Pairing.G1Point(0x1e3069598069906de437450c3ead807e622868a296ec8b4e0ae153b633074c6f,0x414febba94c22f9b4074a2442fe9bd307c6d8f79e7c088e77458cfe8b55d51);
        vk.IC[5] = Pairing.G1Point(0x4825bb295868b7740aa81998a43860e87b67c7c3e7ea479f6e0872db3a88553,0x1ff26b2531037675cda61d267fa6278700a3194e011ce32b158ea9c465a5842e);
        vk.IC[6] = Pairing.G1Point(0x29f9be281e45f3a5907e5ef15e1641957537ac39eb0e94740722a75403d60e4d,0x17b54b2a160b43bf8575520468d17ab0f2ce50a531bb67df94c1e50cdc1328b6);
        vk.IC[7] = Pairing.G1Point(0x1b450c325331b02e2769dbb58c119b9d00b4fbbba4fe24888267586dbcaaf926,0x1ffbacc6426f58f3c1c03b784884c700b4f728eb52cef5f9af0ccdd94c3562ad);
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
