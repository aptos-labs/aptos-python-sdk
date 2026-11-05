"""Unit tests for SLH-DSA-SHA2-128s cryptography (AIP-137).

Vectors:
* HD-derivation vectors are ported from aptos-ts-sdk PR #802
  (``tests/unit/hdKey.test.ts``).
* The public-key / signature vector for the fixed 48-byte seed below was
  cross-verified against two independent FIPS 205 implementations
  (``pqcrypto`` / PQClean and the pure-Python ``slh-dsa`` package):
  the signature was produced by ``slh-dsa`` and must verify here, and
  signatures produced here verify there.
"""

import pytest

from aptos_sdk_v2.bcs import Deserializer, Serializer
from aptos_sdk_v2.crypto.slh_dsa_sha2_128s import (
    SlhDsaSha2128sPrivateKey,
    SlhDsaSha2128sPublicKey,
    SlhDsaSha2128sSignature,
)
from aptos_sdk_v2.errors import InvalidKeyError, InvalidSignatureError

FIXED_SEEDS = bytes(range(48))
FIXED_PUBLIC_KEY_HEX = "202122232425262728292a2b2c2d2e2f990ce6298792b128846a8e4a3a68954c"
# Signature over b"hello aptos" for FIXED_SEEDS, produced by the
# independent ``slh-dsa`` (pure-Python FIPS 205) implementation.
FIXED_SIGNATURE_HEX = (
    "38a43a9ebeebbdeb8853744fe87653e7cd6d61756515cd9d6e25f8a13724394b9d1880d189b4b06497fd7896f1d39b350d4f"
    "edeaa02baa17cc85b080383def058540781fd70f3ddab4cd669c7bff834a704c6926b2303348606d67226d909633c0c63526"
    "515ceab05176b187b42d1a535477d051de40a48629044a9e944d851425456ac34144ae66b62f59612b4a606fca4cd54512f4"
    "2e2a27078366393daf1e69174c8f8f862b1bea9d98b6d874bb59740da906563ab035ac0c2a0706599f988ceb38fd37210b8e"
    "352fcb1e41e82e67f5a81016853b3f283ca59ddbe4ff3dbadd7f64b62e3053b65a6ffb05a9173db7d68119a8d10b453f83c0"
    "01d3f1124a09885aef91e9d2c8008cf7aaa41604e218aa09e6054fc4cdb7b552c967e13c66ea344c7d4c172a4af940cb1303"
    "d99ffa8254cca83cd99db9dd0a212391f3ae1996a634d5d13f9088734edd5381409ce6b4c8e8bf232a497319f081df30b83a"
    "f05bc64f0c16bdefc757241284aef23982d891d2a27df2e73662c3ec815cb6dd959c2836e8e0f56b809ca9a47c081ac641e6"
    "ccfe35523b7bb408d9f46c3db74be629fb48c7928194743f5f55ceb4d44b0d1fb40dabd509b0ebd4dc679b4ae13c8c122189"
    "b9715f09e57b444dd45b63c4211f9cc8ff7811684ff17f6ca63b495a6070aa5d8cc59f21bb58e5b480e85f5fed2aa2cfa14a"
    "64301d27bfac795cb22ba2198ea1a6f9c5acb6cc1a26be6051dda2c604956a0c856629dd42e1cd5ff6502a9e1d63355a7c62"
    "0fce893830edd8395d7b629319057c0c3562cc0c06f51c8466d14d3660dc69ccf0f4de90b7fbc8d2f844c5707eeef8229bdf"
    "f97ebdee3a0ac45cdf543a948e896b930045619f98f102cbd52e8f3ad70ef78697da4c61916b4281b9761dbde3f692c64a74"
    "4484193f8ac3aa9a941c1107f307adfd6c40ba5d3377d9dfcef7926c5941572408908a73224c1a821490dd9c80b1d6c3eb12"
    "b8a5ac72432c163bd32e88ce0099591db2c8a395bc9b74f49156d41b6839c536bde6f56a89aeb3dce9e86395f066a51cb34b"
    "5337bbd5419a634de349789c38d5383787b93b8a9108de8c27788f7915040db4778bbb694d7379d50212648eca580c91b881"
    "6f56e280caa3b41c9712299cc0e9fab1895549b31da7110e87fa32590822d93a54efde80ca246bdec937f0ee3ad22b3b0755"
    "e3b6265ba84ea028e0f4e3d8402b31db0c2bd827a1043426e98ee13f0de065a9dee5e23320224e253fcbb78f9d9cd3e6f5f0"
    "142181e5c8e780158c17cd9f25dd49185b4b94a77c3e93eb34bdfbb156840e007bc3940f957a2182c8127ec2b9c2f808e65e"
    "226a50879f9dfa3dc2955ffa572a08b93608e03265f1393fcef40273138ec4d971025cac8ed5c7e184682a7bf6a509dad1a4"
    "89c1414b477fed7461ef7fe4cf6deebfaab3c8126ee73c95d0f46a195e8aa17cde2b481ccdedf610ed5ee16ecf5991a98516"
    "223a53b0c2d24b651132782f2cfc6f4a72a1b9209f508a4afa6a14cb92e04b64a6f4847f8892f4a11c25384b0b0c05af99bb"
    "09b7a3455d341f3a858b22e8cedc978b81d0e9e67e96356e7b57343f44fce23f10a8d7925c3831e43dd8e07eeef6399dd73c"
    "6b4323d6be916cc2dae6bc8b9ed536edea16c827eeed86201cc949387ac8a81b2f30013483cc96ae494e707e8f88f6d73e1d"
    "6811515e9b09758340c194f68b91f32bdf087ccafcd47b556a37857723a6d0bdc5c8feefcc53d875554a57b1f7fc7d6a8064"
    "985c30562d96b8bb16216b5624504647a3e9cf6420612d7f08b174b529506ebd3525bd3a57abd8b9daa5ce1f77e2a0b0311d"
    "f5c70d4dc53850df98caa21fc0f20352bce71b50ac535f865ca56c8275494147fae3876f632c875de8e356e6c6f9b9111d78"
    "b05e3dfd2435398634a9a96f5a0d5c304c286fefe0b5110a1465a14f644070b020034e855070f7741f8a86f4d1541aab8fd2"
    "16ac2d71cd128e00bc9d06ee82f8e5d5e2bc2d87ef26390b50d9c4ece9cecbd51b2b8c4d72838e3d4ee72179c686ce405403"
    "8774448b416cdbeb45042f16d6c20d372436aebfabd1e74bc2c37be63376592ce472f83d323d60da3771269c158ddb4dc7df"
    "541aa89b1239e5689aaf242475b80dd935fe137470ec0afd5ae0b5bfd77dddc16d3c91ee7b9485ec8fee4efb0f34d3b5a291"
    "32331b6e54f3593ad50db72917027b0cbc23feca6a8a3a12159dfca2f5dc4e9ceaa274b7381bc9ac1c3475a6db8787794a69"
    "4702e73ab215796aa13e62dd455720e322dfab1682e8377494975f538f4bbe1b4b38978a990368d5df767868581bfe3cc505"
    "996e548924f0dfbeaa1d9fdf983f781f97df4ddfc0e1c549741e21574876fa25e92fdb266bdf54a98b4362164f4242df493f"
    "441cf7cad05e0efc9978def034efb84539b8c03878db4429ebd3c2414b7fae3b4e96a5f9fc4f85f075f6b9130f85963fd56f"
    "ac250823e241fd4334ad2280377e9cb9e986c02f535339d634ac1d26a9a473f73e41951d8fe0fa9acc76bb01a6b7a4f383ba"
    "d6ea42f36fd4886b1161826fb12624c18a5cdf0a956161fcb5e343bb1d735017e3ce7ca8e00fa186f1659b2e1b43bb8a35b3"
    "ff889d3c8b706add27798c730573de03e0189f29e7f27742e78cbec27fce6831b226955c3f09b284432b5e94702b6c0f5c28"
    "9114bc4a6cae52cea83987af97b0b1f99751cfa25ddaff6ff869f5444129e229ff5a2cb4ba4988aa7938a66a63325b704a8d"
    "55ac48f61f41ff8475a6f642f6c990cd33e195e8507ee487ca7e60e6c34bebbadd15def07a5bfe413b19be5a0eb2a3c4f4e7"
    "5a05c120e0f5523df11897b8ec10c618af89f630cf67c668ce7a1bdc3d4ac7574c9a18675b5b24c8ffa30c6af01d39c46a25"
    "a955c7399af1e66d80cefe2f37f68fd5aeb2bb51a82d613baa285be3f71c96f3e21d539fd13edc3d8d73ba333cec082568d9"
    "6b6fedf5be675220866843780f695f16075375681a75423a8dea41ef059bd35276ea8e30c05ad15bacee9542d799863b76c0"
    "e14dd68692b32644b85eab625cbb985fbd82745039354483620dfa714549869f55ef6bb66661b6604240b5eebaa1587382fb"
    "fc967b042d6beeb1fab424d289d55ccdf771f9bb0943d3a3078060191886043285f58b48559358a2c45566d255de8040514d"
    "8cfc96cc5d8446ad28fd5a3819b61ff0465c1bdef0921dda0875cfc887aad097b665c221f4acc1d7631d899a2a6585707765"
    "aa53203722b31e42b015f9deed8414d879a792a1b79ed2eee6dbfe314a4c03ee3a12b5aebfd7b6099f31effd27ed4812630b"
    "8d64140b6161ca4b6a57dee847ea0b78a2da3b789a9d5be3a397728bd00a34a6a5317b36d6a81ca8e4cefb8ee8bfe2fb9695"
    "7bcf3974919a137f01091bd3e5c648f1abb022e051e75cb9ab4e7a7481236144bce70c788e34fae94ee03dcacb6bf1ac8f09"
    "330983000a8d7e08f076042fe0c6190257c6025e953bd773b7f021e5a60a6d8a575d4e8b74b42185675b125c3a1afb229cde"
    "bad255454bb59b9947dc35b5a9a7374154413ed57759e0eab750436ede19870ebbbfde9eead83cffdb8a6ffb2e24240ca180"
    "72d3c68f74888fad40cc031baadd96a32452bb47ef9fe6bb2f279b89929aa08a510a208f6722c46650fd4f54725d2988504f"
    "a66d4f58ef5c3466179c7a22dc58352e455beec4b57f65f2387664ee3ae9ee98900262885c48cb7e592658482077b00d1805"
    "996083f1c311a55a83b0ad7c1794861c432384c64b995cf98877cfc9c932babc3fc5f485efc0e46ca5505df1340d0511fa0a"
    "64e351e1eb2761fef95d13e267fe4e5b88355bfe40073c2157c3ee382c58c914c5ecfe611474f5e817617756e21d8eadfac1"
    "b654723dbc3f2e24f74c17acbe88217c6a79a79a207e46d776d97184f724e21411ec8d163014b340336e905c52d74d95586f"
    "1ebf4d0f245dcfcf63696a8ee0862773ee1c25a4645bb0342c39956355ca1ccf2396644f0f21d6d402185761bae309f85712"
    "0924b29d09fac00394394485f3f60d15a9447a2d35586b0ddcef4bd3072ee0ba695ce777c5e3ad42449396598830d676f66d"
    "0a407949d05b9d01caaa0b8059806fa10326a104fc6093dc59c529e3cc3ced9bb573af6f05de20b6db0172be850eece2c49a"
    "da1ef6dbb281039260924678f91606904d53a0babced4d8728f2f583e0182252dc6d5170ed5db827843587489b79bbe85872"
    "1d40ed77c98f2b87b566cf716affe19dbc7c3c4d64bb5af93c5b031fdd6da9cdf8c52664a469698fdfe890a3e4299a502b10"
    "ee3c80f1372f2676b90c4fa43aa35864e741e3c880063b313adbd3d4e378b98175870f66f84757c56d734a485d3207194e94"
    "66f1a52ca59a627f2d7e298ab61ba12468ccc460d5e3e5e53e0230f4f0893262c95ecd7b772f1467deaa7507048b082b1275"
    "bd444d11ba7af8353c7c114686b1b74e3828ed183ebab0763e9a32d5d1622310f7ec6f0bc65360a4f7084138efc5385f0caa"
    "3f71a80c092d53036259e9ba0d9a7720773430ab4bdd99cb3adaa8833cb4705a50c9b853566e8bc8e48ae8cefd2b67e67c41"
    "392b8d0fd75d1afe0c25f4f0698378a8af27cbfc4cedd52d92c5c03ace78cb9e18e0dbe138c2ad4673e9b838fa2278e1a911"
    "077e554f982713b2d5ed2c513b152d93fb0a1786ab72b98800828580098d6e36214fc026eb232b198d14f1c4ca7b003f67c1"
    "89970194cfc4c159943f0b7b47b4efa93569880b37c6f5ce13dea04040351db928c8bc78ba09b0f16cca408614067733de90"
    "8ff02e4e08f96688ecd78de9f0c19f8d2e2cd72589cc93bbbde617f63392daee7b55b3f94219f88e7357153ea73757b25d08"
    "2efbf74ba6093ce71ac1759694cff9b4c5dd7dea6e4954676e843cc69b7c93dff1b302ec571578e777142e37cbbe19731c60"
    "5f154063cb5a6336e1d5cb87cb23fb374deaa7f3ad297980f37c92e5d2b4481a4c1e8900ece4a8c0352208cc8821347da573"
    "f185f852082e2ed7984dc81bfe552b2424e41c95812deeacabe8919b5b56af29c8ab3feebf683b391424b2956dfcacd33dbd"
    "88c7a5ecb328e7f780bc931cc45c7764907daaac905bbeca4920cfcc0d97ef67d9aea0b507ed834876adb5b028f0473b2f7b"
    "0b738b203dce315e98c55a79257b2d1391a4276dec5a576d76bdba9f7ff5e7ae6b38c5bb6c50c5bf7490615f6c5d07e0680a"
    "aa7bedfb913b387459034a6895babdf2faf2d9d66afec34d5acc376ce829e20f81fa4b71164e545cdfe1e1120859c478761b"
    "b7874c640445e527038a137acfaf8f39ce3abd569a11ab6959e18d2a202d3aeb77a9e9cebeafb5b16ad3abf8e3541b9833fd"
    "c86ce3b26ef18c701c65c83ee6c0fb2fe2568f007ae7735ed25938571b213c6e4ecb268b365b51d29d1f2b875cda7ae66804"
    "f1708291bfff4734284f9e74cfde650fd44d2c86764e0510800658fd47cccb2c2678ccfead4c9c26ef75e76edc062a80f653"
    "8435caaabc32a3ff7a1ac90329f7ce98da9b7a177444a8324b3132dcb30e4e2b325837d38059c4de071b55f3edf8c304751e"
    "d165f8ba369a1a9594b208e3d19013b0a6e8cda4cfb20ac7912ce5e3d88fd9a0014447dcfb83cb359262001936af966596e4"
    "db827c67208d645bebd4a363eb10ae6753cab9781ff8fe0e27127463eccc34bc08b3528c85bae4e409cbb59c9f0216d7ee13"
    "3b7dc6ec529d1d9ad4e913051441fd84143bdb188a97ed7fc8f8d4a6da9a7d5e4f1126bdded7b23430b47451ceae08e64d98"
    "d46e0273a541cf4205f369671f8f167ea55f0e9ee329c42247421df2d1526b6e3873ee605339e1ad5d5d26738d1ef026ac8f"
    "046520fd0217eec13be136697b7fca7b8f522cc7ef2b3c8740c04bb59b9023df6eabdfc17b8dbe5368a268332bed10872616"
    "74d2e316f50c1860bae69f74deeb8f698e921817af21c37973f4ea804d8198464d491b05dbc6de9e90c89f2c32402261367e"
    "cfbc3b1596af5e32e8a8c6aeb6ba87eb94ef5765bd7583fbe85bb95918625b66943967a0e8c4fded88271c2e82a36425e665"
    "1684def131faf580990ca5370ce89ab90d8d27a153731f3825e3eb1619fef776320af00eb00daf409506ea55461ebb0cca98"
    "caf2fecc871674e46f2b6621e46b0eef21b4ae31069555ec7dace2cc33e85e94b62b775e5972100f5bc829c9dd85a19028ca"
    "52985197bb2ee49658dd2b71f1022200b084eac3a6689f40666d4f00d3cfdeb1c161841b6ebd9de46745cf7fbef908734b5b"
    "e0774f50ee5d1f051748d897198445614eba7c7dcf210b799463fab72239c7134d22137c1e722ccd31a341237ad9a4309070"
    "180331b04a64a64b4d89544665142f4bfbce5c9730032604d3659382ae8666e0c2cdc51b6a93a6f49b5626a17548bf89c5af"
    "501bdd346cab32e03b707dc4455aaac532001dcd992f24a40139ce3945789aa33ef032b481c097e82d546dc13311d1a94415"
    "7029a858cc433878222ba66a8fd943b863dfa369da1c1160de42f2a42ea90f22e13bef20b6138e1ed43d2d6a7d7088339b90"
    "a2807131feef042b17d3005da427e126457bbcabd1e6c91119323786574755b1c3c43c2cddfec1085b3ad5b0ba42da734aec"
    "cfeb8e99277e34f254c76c379ba881e40c28aad3482d72ba7174bef7481239b077838a8f7ee2ebb9fb94fbbe8018e4978ca1"
    "74c254e3c8e199f79225916f80f4633c4d7d0e9ffc1db2701889b9180ba40e0d925fed3581ed17d5159e709302d4a9a77220"
    "1a3b8881bee1f9c0c1070f90013667133fd4493926e76ecdc4d8a6c537b303666004bec863277c5aaeef29ba6ae6db78616f"
    "1508564df8b599a96c51cebe77dab8d8862e3e5a5e230a12204823f5c09249079bdd572d000c94e095529a6a06d37c1a6669"
    "c2a6f6d0a8e66af58c0b9bb3f3cc42ccaf85cf9a86be45e628f960405434db7d88f93d1a54268286c32c7a9206206ae9d2f3"
    "9496eb64d2b83b725b2dae9900527f68e05b90eb7c47ecafcd40b9373316d324991292d89f7a0b81b9acbdf6c545a0860940"
    "ca14e28b050ed3df603412bd2bc10f79fa63127b082c1d21f56b5ef46b2837032f1feaa2fbef053ace14d80d786b7bbbd190"
    "b9f460173567f44951e1696153b5f4031e9e158de7786f9df74466107e8770b6a3e094719eab13fd1f29ca1783d2fde1b9a6"
    "432e059a6473cc8260dd83fa9785f64f4330405e0c92a304fafb229380350f5d959605629def40c92b6ded25a39f9764aee7"
    "3be4c03c828536c99636195491ba5a6281f30aab1a3723772024c258750c55e53f8b1adc3563c636f7e8d148b08acde67c35"
    "3675d4ff6a7716c21dc4be5e46a25ce27534cfe5af9a660f3f379cb35747e599e21cc02c6dd928994b03d8a78c5f22692ded"
    "51471a14a4a03c92e19f4058f0b2f88ee41e093c58358a3d16a90426f683de8eef4a1388721f07bc386d8f29044841709626"
    "6e5fc4c8b6e2f1c09be438413e237588968ee0a5ee3f61fc00ddf05e6eef23cd9071c7bee1e9bd926a509f4166ea224bd964"
    "9f5579d210a7f1518afedfbeb59b883004b7392da7a67f61d6615ded9688f53f6058b683fcbad830b73e38081496d4a333fe"
    "e704ff35ab073fe121c4f3cd7d2e9a2c891649f610f7472b5e88489b75fee2a5ac9c2d8ecc244b63605cbd10d31fb439f1e3"
    "75612391e769db91a6bf6fd978518fe56f0831e33d78f32fdb730272cefbab75a9d60b1b8efe265b26aa3c7bd820e962337b"
    "53211e3b6ef11f8fefd82f1a7acfd32596e42f9cc5ed2776cfa04df7e33b8347beef5ee80b764e95a0d2d3bc08a54326c06e"
    "06530aa5af3f2fafef66c8357c73a58cf46c0121968e379f687137a802888e1efcb0e0f9b7ff181efbd10c3b165ebb158846"
    "0e0bb7fa252b325cd4d54cf6ea6e5e6947e3d46f59df4bfbd43c1cdfff8e4a574a4f5fcb4fc3856d891a966f74fe1fe7add9"
    "a88fa7bc0c95b39694c12f1ce1b9ba01e3533255e55c816e629ef6d3288b72e2cd3a675d55d17a68ff4b119da1a41024acdd"
    "5eeeba73a64fab9b2d376e4a478f59b386ed8b173bb0bc960545a087570e82fd6ddd5afce1619ea6d6162b959724d81787a6"
    "7ac378e66b120c6a00aef4e00442525579bc24b1355bfc171e01a327e22fb891a5dceb800f286b95d3c44fe71d72f7222be5"
    "89ec2dd85169ef8b6a9ae2bf54243d5194ee98a96df5dce23df7d5ea2aedc02a0d256fafce850c25e2ae140b08e87dac08e1"
    "1066b7987226281daddcde72d254122339362f405526830a9d181ba7a977c81483757c9e534883f544129ff8ab66b15e7462"
    "6f622e3860de6464ef737b29ba0ca3fbfd7b18384507c4d92f0092226fe26f78798a946fd668ed17e886dff116e9de93fc3f"
    "1f9cf7307b096c7bbfbbd2a43f9b726a7914c33349dc7d8bf6a36cbbb12a36e864628e0d996e385d230547b0c6e8b1e51b5a"
    "86fa8ba3ae5b746b1ef3d4eb14f2300f49bfc33e297b6f7b2a67a1949fcd51017c446e72d69b648b2a5f0ebe887f762c85c8"
    "40908084537ea0b1d577b1493ba7c6bd082defdfa8bc237b7c7f28639c9b68e48493aaa4b00e4f3783d9e461be5a9a555c0e"
    "946d09a5d39948f230008e49ea0e84dcbfdec792abf4235dd6efb75829d4f423f7e88fff3c353b7c0af65403df453692f4e5"
    "474246641ffc7fbea9f3537ed1eb14fe14132ebf4c1b3056eb8cd10eebf5db7b60835832d016eddba6cfd479f39d5c68ddb0"
    "e17fccc646ca644b31f587f80455ba938bc50dd9a1caa6de9dd87442e0fd16033832f7702608819eb0cb05f7f83180ddcd02"
    "e031b478be9495d96a29e59c01e3bc09f0e599ad312eeddc650996b029ad042b72cb3af749536ff8778b0537e502c49840b8"
    "ae3d7b7937413cb1a771438197900082fb9dc542d7ab90f26e013031db5e257fdc8c46dac3e3a6b4d329e67b9b8aa7e52ac1"
    "44cd6ef2524ede51af64d23533880b35a0ec3b6656a25718bcee2caa895285b8ad05cbf76f35fd674e2003ca69049f97d64c"
    "6dac4ea2d1a7c46076ab6cb8637e079392c0ff2bd097213f2bc9dab8fe40f8cb486e485379cddd51fa803623b14a7199553f"
    "84a47a7f2d5ef6345cdca514cd66c41708847d553fd414af1a07e59c355cded035e501814635bb6ed1f2948a81fc600b099b"
    "3545c7a700cbe2b240a2a1bb2862a54bbeba88c4dce51dbb726559e54440d5589266e161ac3a2fbd86690102239445cfa5cb"
    "e28717022f417a689ec30df93e1a8564a2f0aa826edb01c0d329d83c0d61557dee1b9cd0f53d14d1c9d01aa781a24ab9a3b2"
    "05bc89a0d4bf2321ac6203e857f13e43ba52db2d599872339a85836e3a3ea4ac7c27be17bf3f5eaf0cf1b2a9e67ea7ea1444"
    "36ca9a7c52770bda5501412067b8512455c94dc949b905911ca19f425809bbb5ca5c76ad59602c7c3c965e2325603417c6b5"
    "63e288bddf511c8587216241abe920d92bd49a17c7f8acdb6133b83a190e77171a18d644b41580e33385f2a329ac94b3959b"
    "14cd1f65ed4badc40911248d98bb794afd09cd2a6b1a4ba395805d36e0892a49db5da9915828e52e6ed60972194bbfde96a4"
    "74268ba10ac5683e99c2b91581213b2497abc92590b2738e402d0baaf986858de90b98207c581b552fca8d2c1aadb52ddda4"
    "e94aa8d5f03bf53fabab22c9a227f13dbb087d783b6af9554174750f294e22b784145bec73066cae48c97e833a6a5a91f4fb"
    "988fa5ee6d9a4e849e4950081000de1f781ccae1cffdacd57c7b165424e2ba4647910483c1e3fa3fba8dac656c64be075844"
    "85bd7fa14b5d95b126e62a6c318f6b915904de04a500e4697117e4f0e273921327f4a32b539948801101d895e121f968936a"
    "c70c674dca98d94b85508dd89e349c4af3ad2a3c54d60695b972c67548962b554837d96c869cdbd47a94811ae53f28595716"
    "564aeaeaa20d0202af3823f6e7b35f1516f12ba5699a0cef2b6ff3ff505e61ff07fafc71f8de12fc021d6163d87098053a7d"
    "e033b109ead1222633ba0e3a8aca36544d6c8c4091fd900c9bc3853795127da0ef737f30e4584e81a0d45771c6350d55ceb4"
    "1d5eb64620936f0cf5c59fe18d262fc6788fc1657f8d848d9745561e34ca2082f6e9a30d950f3e1687710bb048aca22739b6"
    "acc245f17b2309cc90b654e276f70ee1da8bf0d71c5a1c2d4f701ff9c244de5bc833a275a1cb0184e515c0af371f9f385cb4"
    "ae0c9103880bb7b919a76917879e65d9fa5d324f950e13c57fe73160c6834130ae569d3669e5c56e8a12af72708092fd3a1f"
    "8dc4d477642e4ea79c7105fd404f01ef4826258975cc9a730daf0911677a525d9cb7266bcbdeac1a16cf5f009f332b4054f0"
    "54fd32904515a6ec4edf56441e6b093bb52678e303e358a150093720a45d07edaee324a0792883e25b39324fbd22a797f194"
    "c3b848bd29b58cd51294a2863577b88f8a3a05a4d6f08838a5722358c468d42ce316b8cc140f4762ec601aaf06e71fa16c74"
    "07fbf6e7a21878b10989c766b60be448ccfbd0bf79c7c236178f86da273e962cfd147dd68d2eac06101105df2e1608be0689"
    "418f78b773aeef5f50701d5591f88a79d5de79ce80b16950eaf8f0c66a94b306b4386e6628b2c305bd86be3cb8263360b49f"
    "f5114e04c0499e6457e189bac9bec6f0ed21218db0d793f8cd2ca223228c79361ad4a5983fac2bd487ff5bf1cf700a4f2fd1"
    "4e129939d92b72ded73e9120aba139bafceb40154bf095ec3dba4e0ed8d7672d441afc16bd26d3a1ca022e8c67927bb17af7"
    "6b1e9859452354284bbbeebd021a527af2bdfe705428bb6dc52ab7ad7cc178a3e98345ab304c53ddef90bb56684e2de8ffe6"
    "023afbeafa802de9fefe14a8fe4c444e3c8893c1285f73eb1b01d7d6e97975836627e7d8384ad02ed797dfaa2b73b0305f38"
    "036fc98e86e8593cb53c72b86e5b743e2a6db0515ea2d29f0b1b2e87ff1bce694821130b79eeb31d959ea9b5b3dd742bcf03"
    "f31bae18def288fa5ee192a315ec3b85a2251c26dd7d59a2567ed83626c00aeb052727a9af0737bad85cba63005d940ed910"
    "057898ff8ba7"
)


class TestPrivateKey:
    def test_generate(self):
        key = SlhDsaSha2128sPrivateKey.generate()
        assert len(bytes.fromhex(key.hex()[2:])) == SlhDsaSha2128sPrivateKey.LENGTH

    def test_from_str_hex(self):
        key = SlhDsaSha2128sPrivateKey.generate()
        restored = SlhDsaSha2128sPrivateKey.from_str(key.hex())
        assert key == restored

    def test_from_str_aip80(self):
        key = SlhDsaSha2128sPrivateKey.generate()
        aip80 = str(key)
        assert aip80.startswith("slh-dsa-sha2-128s-priv-0x")
        restored = SlhDsaSha2128sPrivateKey.from_str(aip80, strict=True)
        assert key == restored

    def test_from_hex_bytes(self):
        key = SlhDsaSha2128sPrivateKey.generate()
        restored = SlhDsaSha2128sPrivateKey.from_hex(bytes.fromhex(key.hex()[2:]))
        assert key == restored

    def test_strict_rejects_non_aip80(self):
        with pytest.raises(ValueError, match="AIP-80"):
            SlhDsaSha2128sPrivateKey.from_str("0x" + "aa" * 48, strict=True)

    def test_invalid_length(self):
        with pytest.raises(InvalidKeyError):
            SlhDsaSha2128sPrivateKey(b"\x00" * 47)
        with pytest.raises(InvalidKeyError):
            SlhDsaSha2128sPrivateKey.from_hex(b"\x00" * 49)

    def test_eq_and_ne(self):
        a = SlhDsaSha2128sPrivateKey.generate()
        assert a != SlhDsaSha2128sPrivateKey.generate()
        assert a != "x"

    def test_serialize_round_trip(self):
        key = SlhDsaSha2128sPrivateKey.generate()
        ser = Serializer()
        key.serialize(ser)
        assert SlhDsaSha2128sPrivateKey.deserialize(Deserializer(ser.output())) == key


class TestPublicKeyDerivation:
    def test_fixed_seed_public_key(self):
        key = SlhDsaSha2128sPrivateKey(FIXED_SEEDS)
        assert key.public_key().to_crypto_bytes().hex() == FIXED_PUBLIC_KEY_HEX

    def test_public_key_length_and_str(self):
        pub = SlhDsaSha2128sPrivateKey.generate().public_key()
        assert len(pub.to_crypto_bytes()) == SlhDsaSha2128sPublicKey.LENGTH
        assert str(pub).startswith("0x")
        assert SlhDsaSha2128sPublicKey.from_str(str(pub)) == pub

    def test_invalid_length(self):
        with pytest.raises(InvalidKeyError):
            SlhDsaSha2128sPublicKey(b"\x00" * 31)

    def test_serialize_round_trip(self):
        pub = SlhDsaSha2128sPrivateKey.generate().public_key()
        ser = Serializer()
        pub.serialize(ser)
        assert SlhDsaSha2128sPublicKey.deserialize(Deserializer(ser.output())) == pub

    def test_eq_and_ne(self):
        pub = SlhDsaSha2128sPrivateKey.generate().public_key()
        assert pub != SlhDsaSha2128sPrivateKey.generate().public_key()
        assert pub != "x"


class TestSignAndVerify:
    def test_sign_verify(self):
        key = SlhDsaSha2128sPrivateKey.generate()
        sig = key.sign(b"hello aptos")
        assert isinstance(sig, SlhDsaSha2128sSignature)
        assert len(sig.data()) == SlhDsaSha2128sSignature.LENGTH
        assert key.public_key().verify(b"hello aptos", sig)

    def test_wrong_message_fails(self):
        key = SlhDsaSha2128sPrivateKey.generate()
        sig = key.sign(b"hello aptos")
        assert not key.public_key().verify(b"wrong message", sig)

    def test_independent_implementation_signature_verifies(self):
        key = SlhDsaSha2128sPrivateKey(FIXED_SEEDS)
        sig = SlhDsaSha2128sSignature.from_str("0x" + FIXED_SIGNATURE_HEX)
        assert key.public_key().verify(b"hello aptos", sig)
        assert not key.public_key().verify(b"wrong message", sig)

    def test_signature_round_trip(self):
        sig = SlhDsaSha2128sPrivateKey.generate().sign(b"msg")
        ser = Serializer()
        sig.serialize(ser)
        restored = SlhDsaSha2128sSignature.deserialize(Deserializer(ser.output()))
        assert sig == restored
        assert sig != "x"
        assert str(sig).startswith("0x")

    def test_invalid_signature_length(self):
        with pytest.raises(InvalidSignatureError):
            SlhDsaSha2128sSignature(b"\x00" * (SlhDsaSha2128sSignature.LENGTH - 1))
        with pytest.raises(InvalidSignatureError):
            SlhDsaSha2128sSignature.from_str("0x" + "aa" * 10)


class TestHdDerivation:
    """Vectors ported from aptos-ts-sdk PR #802 hdKey.test.ts."""

    SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    VECTORS = [
        (
            "m",
            "53c14b2681fcca8600d3ac7ce3459d6ceece7abc0a3b4c0376fc845c1b6503d6"
            "6c5107d9484171c02f9eb0409849fceb",
        ),
        (
            "m/0'",
            "473049c70d5414379363b94f52de6b194c9f1651cb6a11b80cfee19f6ca67975"
            "201cdbec137ff57e2e9cd434fca0680d",
        ),
        (
            "m/0'/1'",
            "b609bf21df9baae65045e2bb8c200e97fbf86201f58e4187197a60bfc827158e"
            "6ba452ffe50f57849c022b24d01ac123",
        ),
        (
            "m/0'/1'/2'",
            "60b55f07c62916f7f27a96be371a9e87adedb9acabd84d25c41e8aa5c8c326e2"
            "e64024132f8833181bc2ab008541ef2b",
        ),
        (
            "m/0'/1'/2'/2'",
            "fb7242320fc3bc620587cfdfa54c2abed7d034f6c616ade3a9ad1780a099b268"
            "ed7a5bea0297711e997ff199b24bb82b",
        ),
        (
            "m/0'/1'/2'/2'/1000000000'",
            "c72d4e3fb352a785aa375be20e0767ae20edbce1e18de90e0ea6e9d1677d17e8"
            "4a410bb833bf091655dfabde17cc2011",
        ),
    ]

    @pytest.mark.parametrize("path,expected", VECTORS)
    def test_vectors(self, path, expected):
        key = SlhDsaSha2128sPrivateKey.from_derivation_path_inner(path, self.SEED)
        assert key.hex() == f"0x{expected}"

    def test_non_hardened_path_rejected(self):
        with pytest.raises(InvalidKeyError, match="hardened"):
            SlhDsaSha2128sPrivateKey.from_derivation_path_inner("m/0", self.SEED)

    def test_invalid_path_rejected(self):
        with pytest.raises(InvalidKeyError):
            SlhDsaSha2128sPrivateKey.from_derivation_path_inner("x/0'", self.SEED)
        with pytest.raises(InvalidKeyError):
            SlhDsaSha2128sPrivateKey.from_derivation_path_inner("m/x'", self.SEED)

    def test_from_derivation_path_mnemonic(self):
        from aptos_sdk_v2.crypto.mnemonic import generate_mnemonic

        phrase = generate_mnemonic()
        a = SlhDsaSha2128sPrivateKey.from_derivation_path("m/44'/637'/0'/0'/0'", phrase)
        b = SlhDsaSha2128sPrivateKey.from_derivation_path("m/44'/637'/0'/0'/0'", phrase)
        assert a == b


class TestSingleKeyWrappers:
    def test_any_public_key_variant(self):
        from aptos_sdk_v2.crypto.single_key import (
            AnyPublicKey,
            AnyPublicKeyVariant,
            AnySignature,
            AnySignatureVariant,
        )

        key = SlhDsaSha2128sPrivateKey.generate()
        any_pub = AnyPublicKey(key.public_key())
        assert any_pub._variant == AnyPublicKeyVariant.SLH_DSA_SHA2_128S == 5
        sig = AnySignature(key.sign(b"data"))
        assert sig._variant == AnySignatureVariant.SLH_DSA_SHA2_128S == 4
        assert any_pub.verify(b"data", sig)

    def test_any_round_trips(self):
        from aptos_sdk_v2.crypto.single_key import AnyPublicKey, AnySignature

        key = SlhDsaSha2128sPrivateKey.generate()
        for obj, cls in [
            (AnyPublicKey(key.public_key()), AnyPublicKey),
            (AnySignature(key.sign(b"data")), AnySignature),
        ]:
            ser = Serializer()
            obj.serialize(ser)
            assert cls.deserialize(Deserializer(ser.output())) == obj

    def test_any_public_key_bcs_layout(self):
        """BCS: variant 5 (ULEB128) || length-prefixed 32-byte key."""
        from aptos_sdk_v2.crypto.single_key import AnyPublicKey

        pub = SlhDsaSha2128sPrivateKey(FIXED_SEEDS).public_key()
        ser = Serializer()
        AnyPublicKey(pub).serialize(ser)
        assert ser.output() == b"\x05\x20" + pub.to_crypto_bytes()


class TestAccountIntegration:
    def test_generate_account(self):
        from aptos_sdk_v2 import Account

        account = Account.generate_slh_dsa_sha2_128s()
        assert isinstance(account.private_key, SlhDsaSha2128sPrivateKey)
        # Address must be the SingleKey (scheme 0x02) derivation.
        from aptos_sdk_v2.crypto.authentication_key import AuthenticationKey
        from aptos_sdk_v2.crypto.single_key import AnyPublicKey

        expected = AuthenticationKey.from_public_key(
            AnyPublicKey(account.public_key)  # type: ignore[arg-type]
        ).account_address()
        assert account.address == expected

    def test_from_private_key_and_authentication_key(self):
        from aptos_sdk_v2 import Account
        from aptos_sdk_v2.crypto.authentication_key import AuthenticationKey

        key = SlhDsaSha2128sPrivateKey(FIXED_SEEDS)
        account = Account.from_private_key(key)
        direct = AuthenticationKey.from_public_key(key.public_key()).account_address()
        assert account.address == direct

    def test_from_mnemonic(self):
        from aptos_sdk_v2 import Account
        from aptos_sdk_v2.crypto.mnemonic import (
            derive_slh_dsa_sha2_128s_private_key,
            generate_mnemonic,
        )

        phrase = generate_mnemonic()
        account = Account.from_mnemonic(phrase, slh_dsa_sha2_128s=True)
        assert account.private_key == derive_slh_dsa_sha2_128s_private_key(phrase)
        with pytest.raises(ValueError, match="Only one"):
            Account.from_mnemonic(phrase, secp256k1=True, slh_dsa_sha2_128s=True)

    def test_derive_from_mnemonic_rejects_bad_inputs(self):
        from aptos_sdk_v2.crypto.mnemonic import (
            derive_slh_dsa_sha2_128s_private_key,
            generate_mnemonic,
        )
        from aptos_sdk_v2.errors import InvalidMnemonicError

        with pytest.raises(InvalidMnemonicError):
            derive_slh_dsa_sha2_128s_private_key("not a valid mnemonic phrase")
        phrase = generate_mnemonic()
        with pytest.raises(InvalidMnemonicError):
            derive_slh_dsa_sha2_128s_private_key(phrase, "m/44'/637'/0'/0'/0")
        with pytest.raises(InvalidMnemonicError):
            derive_slh_dsa_sha2_128s_private_key(phrase, "m/44'/637'/x'/0'/0'")

    def test_sign_transaction_single_sender(self):
        from aptos_sdk_v2 import Account
        from aptos_sdk_v2.transactions import RawTransaction
        from aptos_sdk_v2.transactions.authenticator import AccountAuthenticator

        account = Account.generate_slh_dsa_sha2_128s()
        raw = RawTransaction(
            sender=account.address,
            sequence_number=0,
            payload=_entry_payload(),
            max_gas_amount=100_000,
            gas_unit_price=100,
            expiration_timestamps_secs=9999999999,
            chain_id=4,
        )
        authenticator = raw.sign(account.private_key)
        assert authenticator.variant == AccountAuthenticator.SINGLE_KEY
        assert authenticator.verify(raw.keyed())
        ser = Serializer()
        authenticator.serialize(ser)
        restored = AccountAuthenticator.deserialize(Deserializer(ser.output()))
        assert restored == authenticator
        assert restored.verify(raw.keyed())

    def test_sign_transaction_simulated(self):
        from aptos_sdk_v2 import Account
        from aptos_sdk_v2.transactions import RawTransaction

        account = Account.generate_slh_dsa_sha2_128s()
        raw = RawTransaction(
            sender=account.address,
            sequence_number=0,
            payload=_entry_payload(),
            max_gas_amount=100_000,
            gas_unit_price=100,
            expiration_timestamps_secs=9999999999,
            chain_id=4,
        )
        authenticator = raw.sign_simulated(account.public_key)  # type: ignore[arg-type]
        ser = Serializer()
        authenticator.serialize(ser)
        assert len(ser.output()) > SlhDsaSha2128sSignature.LENGTH


def _entry_payload():
    from aptos_sdk_v2.transactions import EntryFunction, TransactionArgument, TransactionPayload
    from aptos_sdk_v2.types import AccountAddress, TypeTag

    return TransactionPayload(
        EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag.from_str("0x1::aptos_coin::AptosCoin")],
            [
                TransactionArgument(AccountAddress.from_str("0x2"), Serializer.struct),
                TransactionArgument(100, Serializer.u64),
            ],
        )
    )


class TestMultiSignerFlows:
    """SLH-DSA signers must work wherever an AccountAuthenticator is used."""

    def _raw(self, sender):
        from aptos_sdk_v2.transactions import RawTransaction

        return RawTransaction(
            sender=sender,
            sequence_number=0,
            payload=_entry_payload(),
            max_gas_amount=100_000,
            gas_unit_price=100,
            expiration_timestamps_secs=9999999999,
            chain_id=4,
        )

    def test_multi_agent_with_slh_sender(self):
        from aptos_sdk_v2 import Account
        from aptos_sdk_v2.transactions import MultiAgentRawTransaction, SignedTransaction
        from aptos_sdk_v2.transactions.authenticator import (
            Authenticator,
            MultiAgentAuthenticator,
        )

        sender = Account.generate_slh_dsa_sha2_128s()
        secondary = Account.generate()
        raw_multi = MultiAgentRawTransaction(self._raw(sender.address), [secondary.address])
        authenticator = Authenticator(
            MultiAgentAuthenticator(
                raw_multi.sign(sender.private_key),
                [(secondary.address, raw_multi.sign(secondary.private_key))],
            )
        )
        signed = SignedTransaction(raw_multi.inner(), authenticator)
        assert signed.verify()
        ser = Serializer()
        signed.serialize(ser)
        restored = SignedTransaction.deserialize(Deserializer(ser.output()))
        assert restored.verify()

    def test_fee_payer_with_slh_fee_payer(self):
        from aptos_sdk_v2 import Account
        from aptos_sdk_v2.transactions import FeePayerRawTransaction, SignedTransaction
        from aptos_sdk_v2.transactions.authenticator import (
            Authenticator,
            FeePayerAuthenticator,
        )

        sender = Account.generate()
        fee_payer = Account.generate_slh_dsa_sha2_128s()
        raw = self._raw(sender.address)
        raw_fp = FeePayerRawTransaction(raw, [], fee_payer.address)
        authenticator = Authenticator(
            FeePayerAuthenticator(
                raw_fp.sign(sender.private_key),
                [],
                (fee_payer.address, raw_fp.sign(fee_payer.private_key)),
            )
        )
        signed = SignedTransaction(raw, authenticator)
        assert signed.verify()
        ser = Serializer()
        signed.serialize(ser)
        restored = SignedTransaction.deserialize(Deserializer(ser.output()))
        assert restored.verify()


class TestOptionalBackend:
    def test_sign_without_pqcrypto_raises_actionable_error(self, monkeypatch):
        import sys

        monkeypatch.setitem(sys.modules, "pqcrypto", None)
        monkeypatch.setitem(sys.modules, "pqcrypto.sign", None)
        key = SlhDsaSha2128sPrivateKey(FIXED_SEEDS)
        with pytest.raises(ImportError, match="pqcrypto"):
            key.sign(b"hello aptos")
