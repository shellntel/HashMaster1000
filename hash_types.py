"""
hash_types.py - Hash type identification for Hash Master 1000

Contains example hashes and patterns for identifying hash types in potfiles.
Based on hashcat hash mode documentation: https://hashcat.net/wiki/doku.php?id=example_hashes

Note: The password for all example hashes is "hashcat" unless otherwise noted.
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Tuple


@dataclass
class HashType:
    """Represents a hash type with its identification characteristics."""
    mode: int                    # Hashcat mode number
    name: str                    # Human-readable name
    example: str                 # Example hash
    pattern: str                 # Regex pattern to match this hash type
    length: Optional[int] = None # Fixed length if applicable
    prefix: Optional[str] = None # Common prefix if applicable
    category: str = "Other"      # Category grouping


# Hash type definitions organized by category
HASH_TYPES: List[HashType] = [
    # ===========================================
    # Raw/Unsalted Hashes
    # ===========================================
    HashType(
        mode=0,
        name="MD5",
        example="8743b52063cd84097a65d1633f5c74f5",
        pattern=r"^[a-fA-F0-9]{32}$",
        length=32,
        category="Raw Hash"
    ),
    HashType(
        mode=100,
        name="SHA1",
        example="b89eaac7e61417341b710b727768294d0e6a277b",
        pattern=r"^[a-fA-F0-9]{40}$",
        length=40,
        category="Raw Hash"
    ),
    HashType(
        mode=1300,
        name="SHA2-224",
        example="e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198",
        pattern=r"^[a-fA-F0-9]{56}$",
        length=56,
        category="Raw Hash"
    ),
    HashType(
        mode=1400,
        name="SHA2-256",
        example="127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935",
        pattern=r"^[a-fA-F0-9]{64}$",
        length=64,
        category="Raw Hash"
    ),
    HashType(
        mode=10800,
        name="SHA2-384",
        example="07371af1ca1f69ec6fb17b22d0da0d933726b6e71eca4fd95c3a5e7e6f3b0c53f38b89e3ce8d9eb9b0dbec9b39e6a4e6",
        pattern=r"^[a-fA-F0-9]{96}$",
        length=96,
        category="Raw Hash"
    ),
    HashType(
        mode=1700,
        name="SHA2-512",
        example="82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f",
        pattern=r"^[a-fA-F0-9]{128}$",
        length=128,
        category="Raw Hash"
    ),
    HashType(
        mode=17300,
        name="SHA3-224",
        example="ea6de0d8fb0803e10c84ba27b29f8b0b5f9b9f0d5d7a3a3f7f9a8b6c",
        pattern=r"^[a-fA-F0-9]{56}$",
        length=56,
        category="Raw Hash"
    ),
    HashType(
        mode=17400,
        name="SHA3-256",
        example="36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80",
        pattern=r"^[a-fA-F0-9]{64}$",
        length=64,
        category="Raw Hash"
    ),
    HashType(
        mode=17500,
        name="SHA3-384",
        example="720aca7c8d1a8e79c9bc7d8e9b9a0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",
        pattern=r"^[a-fA-F0-9]{96}$",
        length=96,
        category="Raw Hash"
    ),
    HashType(
        mode=17600,
        name="SHA3-512",
        example="9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14",
        pattern=r"^[a-fA-F0-9]{128}$",
        length=128,
        category="Raw Hash"
    ),
    HashType(
        mode=6000,
        name="RIPEMD-160",
        example="012cb9b334ec1aeb71a9c8ce85586082467f7eb6",
        pattern=r"^[a-fA-F0-9]{40}$",
        length=40,
        category="Raw Hash"
    ),
    HashType(
        mode=6100,
        name="Whirlpool",
        example="7ca8eaaaa15eaa4c038b4c47b9313e92da827c06940e69947f85bc0fbef3eb8fd254da220ad9e208b6b28f6bb9be31dd760f1fdb26112f83ff7571a8673f19b0",
        pattern=r"^[a-fA-F0-9]{128}$",
        length=128,
        category="Raw Hash"
    ),

    # ===========================================
    # Windows/Active Directory
    # ===========================================
    HashType(
        mode=1000,
        name="NTLM",
        example="b4b9b02e6f09a9bd760f388b67351e2b",
        pattern=r"^[a-fA-F0-9]{32}$",
        length=32,
        category="Windows"
    ),
    HashType(
        mode=3000,
        name="LM",
        example="299bd128c1101fd6",
        pattern=r"^[a-fA-F0-9]{16}$",
        length=16,
        category="Windows"
    ),
    HashType(
        mode=5500,
        name="NetNTLMv1 / NetNTLMv1+ESS",
        example="u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c",
        pattern=r"^[^:]+::[^:]*:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$",
        category="Windows"
    ),
    HashType(
        mode=27000,
        name="NetNTLMv1 / NetNTLMv1+ESS (NT)",
        example="u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c",
        pattern=r"^[^:]+::[^:]*:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$",
        category="Windows"
    ),
    HashType(
        mode=5600,
        name="NetNTLMv2",
        example="admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030",
        pattern=r"^[^:]+::[^:]*:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$",
        category="Windows"
    ),
    HashType(
        mode=27100,
        name="NetNTLMv2 (NT)",
        example="admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030",
        pattern=r"^[^:]+::[^:]*:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$",
        category="Windows"
    ),
    HashType(
        mode=1100,
        name="Domain Cached Credentials (DCC), MS Cache",
        example="4dd8965d1d476fa0d026722989a6b772:3060147285011",
        pattern=r"^[a-fA-F0-9]{32}:[^:]+$",
        category="Windows"
    ),
    HashType(
        mode=2100,
        name="Domain Cached Credentials 2 (DCC2), MS Cache 2",
        example="$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f",
        pattern=r"^\$DCC2\$\d+#[^#]+#[a-fA-F0-9]{32}$",
        prefix="$DCC2$",
        category="Windows"
    ),
    HashType(
        mode=13100,
        name="Kerberos 5, etype 23, TGS-REP",
        example="$krb5tgs$23$*user$realm$test/spn*$63386d22d359fe42230300d56852c9eb$a]...",
        pattern=r"^\$krb5tgs\$23\$",
        prefix="$krb5tgs$23$",
        category="Windows"
    ),
    HashType(
        mode=18200,
        name="Kerberos 5, etype 23, AS-REP",
        example="$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$...",
        pattern=r"^\$krb5asrep\$23\$",
        prefix="$krb5asrep$23$",
        category="Windows"
    ),
    HashType(
        mode=19600,
        name="Kerberos 5, etype 17, TGS-REP",
        example="$krb5tgs$17$user$realm$*$...",
        pattern=r"^\$krb5tgs\$17\$",
        prefix="$krb5tgs$17$",
        category="Windows"
    ),
    HashType(
        mode=19700,
        name="Kerberos 5, etype 18, TGS-REP",
        example="$krb5tgs$18$user$realm$*$...",
        pattern=r"^\$krb5tgs\$18\$",
        prefix="$krb5tgs$18$",
        category="Windows"
    ),
    HashType(
        mode=19800,
        name="Kerberos 5, etype 17, Pre-Auth",
        example="$krb5pa$17$...",
        pattern=r"^\$krb5pa\$17\$",
        prefix="$krb5pa$17$",
        category="Windows"
    ),
    HashType(
        mode=19900,
        name="Kerberos 5, etype 18, Pre-Auth",
        example="$krb5pa$18$...",
        pattern=r"^\$krb5pa\$18\$",
        prefix="$krb5pa$18$",
        category="Windows"
    ),

    # ===========================================
    # Unix/Linux
    # ===========================================
    HashType(
        mode=500,
        name="md5crypt, MD5 (Unix)",
        example="$1$28772684$iEwNOgGugqO9.bIz5sk8k/",
        pattern=r"^\$1\$[./a-zA-Z0-9]{1,8}\$[./a-zA-Z0-9]{22}$",
        prefix="$1$",
        category="Unix"
    ),
    HashType(
        mode=1800,
        name="sha512crypt, SHA512 (Unix)",
        example="$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/",
        pattern=r"^\$6\$[^$]+\$[./a-zA-Z0-9]{86}$",
        prefix="$6$",
        category="Unix"
    ),
    HashType(
        mode=1500,
        name="descrypt, DES (Unix), Traditional DES",
        example="48c/R8JAv757A",
        pattern=r"^[./a-zA-Z0-9]{13}$",
        length=13,
        category="Unix"
    ),
    HashType(
        mode=7400,
        name="sha256crypt, SHA256 (Unix)",
        example="$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD",
        pattern=r"^\$5\$(rounds=\d+\$)?[^$]+\$[./a-zA-Z0-9]{43}$",
        prefix="$5$",
        category="Unix"
    ),
    HashType(
        mode=3200,
        name="bcrypt",
        example="$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6",
        pattern=r"^\$2[aby]?\$\d{2}\$[./a-zA-Z0-9]{53}$",
        prefix="$2",
        category="Unix"
    ),
    HashType(
        mode=7000,
        name="FortiGate (FortiOS)",
        example="AK1AAECAwQFBgcICRARNGqgeC3is8gv2xWWRony9NJnDgE=",
        pattern=r"^AK1[A-Za-z0-9+/=]{44}$",
        prefix="AK1",
        category="Network"
    ),
    HashType(
        mode=22,
        name="Juniper NetScreen/SSG (ScreenOS)",
        example="nNxKL2rOEkbBc9BFLsVGgvJYvQYXg0R",
        pattern=r"^[a-zA-Z0-9]{30}$",
        length=30,
        category="Network"
    ),
    HashType(
        mode=501,
        name="Juniper IVE",
        example="3u+UR6n8AgABAAAAHxxdXKmiOmUoqKnZlf8lTOhlPYy93EAkbPfs5+49YLFd/B1+omSKbW7DoqNM40/EeVnwJ8kYoXv9zy9D5C5m5A==",
        pattern=r"^[a-zA-Z0-9+/=]{100,}$",
        category="Network"
    ),

    # ===========================================
    # Web Applications
    # ===========================================
    HashType(
        mode=400,
        name="phpass, WordPress (MD5), Joomla (MD5)",
        example="$P$984478476IagS59wHZvyQMArzfx58u.",
        pattern=r"^\$P\$[./a-zA-Z0-9]{31}$",
        prefix="$P$",
        category="Web"
    ),
    HashType(
        mode=2811,
        name="MyBB 1.2+, IPB2+ (Invision Power Board)",
        example="8d2129083ef35f4b365d5d87487e1207:47204",
        pattern=r"^[a-fA-F0-9]{32}:\d+$",
        category="Web"
    ),
    HashType(
        mode=2611,
        name="vBulletin < v3.8.5",
        example="16780ba78d2d5f02f3202901c1b6d975:568",
        pattern=r"^[a-fA-F0-9]{32}:\d+$",
        category="Web"
    ),
    HashType(
        mode=2711,
        name="vBulletin >= v3.8.5",
        example="bf366348c53ddcfbd16e63edfbd24230:341355614",
        pattern=r"^[a-fA-F0-9]{32}:\d+$",
        category="Web"
    ),
    HashType(
        mode=121,
        name="SMF (Simple Machines Forum) >= v1.1",
        example="ecf076ce9d6ed3624a9332112b1cd67b236f1b6c:123456",
        pattern=r"^[a-fA-F0-9]{40}:[^:]+$",
        category="Web"
    ),
    HashType(
        mode=11,
        name="Joomla < 2.5.18",
        example="19e0e8d91c722e7091ca7a6a6fb0f4fa:54718031842521651757785603028777",
        pattern=r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$",
        category="Web"
    ),
    HashType(
        mode=21,
        name="osCommerce, xt:Commerce",
        example="374996a5e8a5e57fd97d893f7df79824:36",
        pattern=r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]+$",
        category="Web"
    ),
    HashType(
        mode=124,
        name="Django (SHA-1)",
        example="sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013",
        pattern=r"^sha1\$[^$]+\$[a-fA-F0-9]{40}$",
        prefix="sha1$",
        category="Web"
    ),
    HashType(
        mode=10000,
        name="Django (PBKDF2-SHA256)",
        example="pbkdf2_sha256$20000$H0dPx8NeajVu$GiC4k5kqbbR9qWBlsRgDywNqC2vd9kqfk7zdorEnNas=",
        pattern=r"^pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/=]+$",
        prefix="pbkdf2_sha256$",
        category="Web"
    ),

    # ===========================================
    # Database
    # ===========================================
    HashType(
        mode=200,
        name="MySQL323",
        example="7196759210defdc0",
        pattern=r"^[a-fA-F0-9]{16}$",
        length=16,
        category="Database"
    ),
    HashType(
        mode=300,
        name="MySQL4.1/MySQL5",
        example="*fcf7c1b8749cf99d88e5f34271d636178fb5d130",
        pattern=r"^\*?[a-fA-F0-9]{40}$",
        length=None,  # Length varies due to optional * prefix
        category="Database"
    ),
    HashType(
        mode=112,
        name="Oracle S: Type (Oracle 11+)",
        example="ac5f1e62d21fd0529428b84d42e8955b04966703:38445748184477378130",
        pattern=r"^[a-fA-F0-9]{40}:\d+$",
        category="Database"
    ),
    HashType(
        mode=12300,
        name="Oracle T: Type (Oracle 12+)",
        example="78281A9C0CF626BD05EFC4F41B515B61D6C4D95A250CD4A605CA0EF97168D670EBCB5673B6F5A2FB9CC4E0C0101E659",
        pattern=r"^[A-F0-9]{160}$",
        length=160,
        category="Database"
    ),
    HashType(
        mode=131,
        name="MSSQL (2000)",
        example="0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578",
        pattern=r"^0x0100[a-fA-F0-9]{88}$",
        prefix="0x0100",
        category="Database"
    ),
    HashType(
        mode=132,
        name="MSSQL (2005)",
        example="0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe",
        pattern=r"^0x0100[a-fA-F0-9]{52}$",
        prefix="0x0100",
        category="Database"
    ),
    HashType(
        mode=1731,
        name="MSSQL (2012, 2014)",
        example="0x02000102030405060708090a0b0c0d0e0f10111213141516171819...",
        pattern=r"^0x0200[a-fA-F0-9]+$",
        prefix="0x0200",
        category="Database"
    ),
    HashType(
        mode=8000,
        name="Sybase ASE",
        example="0xc00778168388631428230545ed2c976790af96768afa0806fe6c0da3b28f3e132137eac56f9bad027ea2",
        pattern=r"^0xc007[a-fA-F0-9]+$",
        prefix="0xc007",
        category="Database"
    ),
    HashType(
        mode=1421,
        name="hMailServer",
        example="8fe7ca27a17adc337cd892b1d959b4e487b8f0ef09e32214f44fb1b07e461c532e9ec3",
        pattern=r"^[a-fA-F0-9]{70}$",
        length=70,
        category="Database"
    ),
    HashType(
        mode=11100,
        name="PostgreSQL CRAM (MD5)",
        example="$postgres$user*MDXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        pattern=r"^\$postgres\$",
        prefix="$postgres$",
        category="Database"
    ),

    # ===========================================
    # Salted Hashes
    # ===========================================
    HashType(
        mode=10,
        name="md5($pass.$salt)",
        example="01dfae6e5d4d90d9892622325959afbe:7050461",
        pattern=r"^[a-fA-F0-9]{32}:[^:]+$",
        category="Salted Hash"
    ),
    HashType(
        mode=20,
        name="md5($salt.$pass)",
        example="f0fda58630310a6dd91a7d8f0a4ceda2:4225637426",
        pattern=r"^[a-fA-F0-9]{32}:\d+$",
        category="Salted Hash"
    ),
    HashType(
        mode=110,
        name="sha1($pass.$salt)",
        example="2fc5a684737ce1bf7b3b239df432416e0dd07357:2014",
        pattern=r"^[a-fA-F0-9]{40}:\d+$",
        category="Salted Hash"
    ),
    HashType(
        mode=120,
        name="sha1($salt.$pass)",
        example="cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024",
        pattern=r"^[a-fA-F0-9]{40}:\d+$",
        category="Salted Hash"
    ),
    HashType(
        mode=1410,
        name="sha256($pass.$salt)",
        example="c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4:53743528",
        pattern=r"^[a-fA-F0-9]{64}:[^:]+$",
        category="Salted Hash"
    ),
    HashType(
        mode=1420,
        name="sha256($salt.$pass)",
        example="eb368a2dfd38b405f014118c7d9747fcc97f4f0ee75c05963cd9da6ee65ef498:560407001617",
        pattern=r"^[a-fA-F0-9]{64}:\d+$",
        category="Salted Hash"
    ),
    HashType(
        mode=1710,
        name="sha512($pass.$salt)",
        example="e5c3ede3e49fb86592fb03f471c35ba13e8d89b8ab65142c9a8fdafb635fa2223c24e5558fd9313e8995019dcbec1fb584146b7bb12685c7765fc8c0d51379fd:6352283260",
        pattern=r"^[a-fA-F0-9]{128}:[^:]+$",
        category="Salted Hash"
    ),
    HashType(
        mode=1720,
        name="sha512($salt.$pass)",
        example="976b451818634a1e2acba682da3fd6efa72adf8a7a08d7939550c244b237c72c7d42367544e826c0c83fe5c02f97c0373b6b1386cc794bf0d21d2df01bb9c08a:2613516180127",
        pattern=r"^[a-fA-F0-9]{128}:\d+$",
        category="Salted Hash"
    ),

    # ===========================================
    # HMAC
    # ===========================================
    HashType(
        mode=50,
        name="HMAC-MD5 (key = $pass)",
        example="fc741db0a2968c39d9c2a5cc75b05370:1234",
        pattern=r"^[a-fA-F0-9]{32}:[^:]+$",
        category="HMAC"
    ),
    HashType(
        mode=150,
        name="HMAC-SHA1 (key = $pass)",
        example="bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824:1234",
        pattern=r"^[a-fA-F0-9]{40}:[^:]+$",
        category="HMAC"
    ),
    HashType(
        mode=1450,
        name="HMAC-SHA256 (key = $pass)",
        example="abaf88d66bf2334a4a8b207cc61a96fb46c3e38e882e6f6f886742f688b8588c:1234",
        pattern=r"^[a-fA-F0-9]{64}:[^:]+$",
        category="HMAC"
    ),
    HashType(
        mode=1750,
        name="HMAC-SHA512 (key = $pass)",
        example="94cb9e31137913665dbea7b058e10be5f050cc356062a2c9679ed0ad6119648e7be620e9d4e1199220cd02b9efb2b1c78234fa1000c917f9139e30d1f46db9f:1234",
        pattern=r"^[a-fA-F0-9]{128}:[^:]+$",
        category="HMAC"
    ),

    # ===========================================
    # Archive/File Encryption
    # ===========================================
    HashType(
        mode=13600,
        name="WinZip",
        example="$zip2$*0*3*0*b5d2b7bf57ad5e86a55c400509c672bd*d218*0**ca3d736d03a34165cfa9*$/zip2$",
        pattern=r"^\$zip2\$",
        prefix="$zip2$",
        category="Archive"
    ),
    HashType(
        mode=11600,
        name="7-Zip",
        example="$7z$0$19$0$salt$files$size$...",
        pattern=r"^\$7z\$",
        prefix="$7z$",
        category="Archive"
    ),
    HashType(
        mode=13000,
        name="RAR3-hp",
        example="$RAR3$*0*45109af8ab5f297a*...",
        pattern=r"^\$RAR3\$",
        prefix="$RAR3$",
        category="Archive"
    ),
    HashType(
        mode=13200,
        name="AxCrypt",
        example="$axcrypt$*1*...",
        pattern=r"^\$axcrypt\$",
        prefix="$axcrypt$",
        category="Archive"
    ),
    HashType(
        mode=23700,
        name="RAR3-p (Compressed)",
        example="$RAR3$*1*...",
        pattern=r"^\$RAR3\$\*1\*",
        prefix="$RAR3$*1*",
        category="Archive"
    ),
    HashType(
        mode=23800,
        name="RAR3-p (Uncompressed)",
        example="$RAR3$*0*...",
        pattern=r"^\$RAR3\$\*0\*",
        prefix="$RAR3$*0*",
        category="Archive"
    ),
    HashType(
        mode=12500,
        name="RAR3-hp (with type)",
        example="$RAR3$*0*...",
        pattern=r"^\$RAR3\$",
        prefix="$RAR3$",
        category="Archive"
    ),
    HashType(
        mode=13400,
        name="KeePass 1 (AES/Twofish) and KeePass 2 (AES)",
        example="$keepass$*1*...",
        pattern=r"^\$keepass\$",
        prefix="$keepass$",
        category="Password Manager"
    ),
    HashType(
        mode=23300,
        name="KeePass 2 (AES)",
        example="$keepass$*2*...",
        pattern=r"^\$keepass\$\*2\*",
        prefix="$keepass$*2*",
        category="Password Manager"
    ),
    HashType(
        mode=15500,
        name="JKS Java Key Store Private Keys (SHA1)",
        example="$jksprivk$*...",
        pattern=r"^\$jksprivk\$",
        prefix="$jksprivk$",
        category="Certificate"
    ),
    HashType(
        mode=16200,
        name="Apple Secure Notes",
        example="$ASN$*...",
        pattern=r"^\$ASN\$",
        prefix="$ASN$",
        category="Apple"
    ),

    # ===========================================
    # Cryptocurrency
    # ===========================================
    HashType(
        mode=11300,
        name="Bitcoin/Litecoin wallet.dat",
        example="$bitcoin$64$...",
        pattern=r"^\$bitcoin\$",
        prefix="$bitcoin$",
        category="Cryptocurrency"
    ),
    HashType(
        mode=15200,
        name="Blockchain, My Wallet",
        example="$blockchain$v2$...",
        pattern=r"^\$blockchain\$",
        prefix="$blockchain$",
        category="Cryptocurrency"
    ),
    HashType(
        mode=12700,
        name="Blockchain, My Wallet, V2",
        example="$blockchain$v2$5000$...",
        pattern=r"^\$blockchain\$v2\$",
        prefix="$blockchain$v2$",
        category="Cryptocurrency"
    ),
    HashType(
        mode=16600,
        name="Electrum Wallet (Salt-Type 1-3)",
        example="$electrum$1*...",
        pattern=r"^\$electrum\$",
        prefix="$electrum$",
        category="Cryptocurrency"
    ),
    HashType(
        mode=21700,
        name="Electrum Wallet (Salt-Type 4)",
        example="$electrum$4*...",
        pattern=r"^\$electrum\$4\*",
        prefix="$electrum$4*",
        category="Cryptocurrency"
    ),
    HashType(
        mode=21800,
        name="Electrum Wallet (Salt-Type 5)",
        example="$electrum$5*...",
        pattern=r"^\$electrum\$5\*",
        prefix="$electrum$5*",
        category="Cryptocurrency"
    ),

    # ===========================================
    # Network Protocols
    # ===========================================
    HashType(
        mode=22000,
        name="WPA-PBKDF2-PMKID+EAPOL",
        example="WPA*01*...",
        pattern=r"^WPA\*",
        prefix="WPA*",
        category="WiFi"
    ),
    HashType(
        mode=22001,
        name="WPA-PMK-PMKID+EAPOL",
        example="WPA*01*...",
        pattern=r"^WPA\*",
        prefix="WPA*",
        category="WiFi"
    ),
    HashType(
        mode=2500,
        name="WPA-EAPOL-PBKDF2 (legacy)",
        example="[binary hash capture format]",
        pattern=r"^[a-fA-F0-9]+\*[a-fA-F0-9]+\*",
        category="WiFi"
    ),
    HashType(
        mode=16800,
        name="WPA-PMKID-PBKDF2",
        example="2582a8281bf9d4308d6f5731d0e61c61*...",
        pattern=r"^[a-fA-F0-9]{32}\*",
        category="WiFi"
    ),
    HashType(
        mode=7500,
        name="Kerberos 5, etype 23, AS-REQ Pre-Auth",
        example="$krb5pa$23$...",
        pattern=r"^\$krb5pa\$23\$",
        prefix="$krb5pa$23$",
        category="Network"
    ),
    HashType(
        mode=8300,
        name="DNSSEC (NSEC3)",
        example="7b5n74kq8r441blc2c5qbbat19baj79r:.lvd-hmr8d256lh:example.local:3:25",
        pattern=r"^[a-z0-9]+:\.[^:]+:[^:]+:\d+:\d+$",
        category="Network"
    ),
    HashType(
        mode=16100,
        name="TACACS+",
        example="$tacacs-plus$0$...",
        pattern=r"^\$tacacs-plus\$",
        prefix="$tacacs-plus$",
        category="Network"
    ),
    HashType(
        mode=9100,
        name="Lotus Notes/Domino 8",
        example="(HsjFebq0Kh9kH7aAZYc7kY30mC30mC3KmC30mCluagXrvWKj1)",
        pattern=r"^\([A-Za-z0-9]{49}\)$",
        category="Enterprise"
    ),
    HashType(
        mode=9200,
        name="Cisco-IOS $8$ (PBKDF2-SHA256)",
        example="$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk",
        pattern=r"^\$8\$",
        prefix="$8$",
        category="Network"
    ),
    HashType(
        mode=9300,
        name="Cisco-IOS $9$ (scrypt)",
        example="$9$2MJBozw/9R3UsU$2lFhcKvpghcyw8deP25GOfyZaagyUOGBymkryvOdfo6",
        pattern=r"^\$9\$",
        prefix="$9$",
        category="Network"
    ),
    HashType(
        mode=5700,
        name="Cisco-IOS type 4 (SHA256)",
        example="2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI",
        pattern=r"^[A-Za-z0-9./]{43}$",
        length=43,
        category="Network"
    ),

    # ===========================================
    # Other/Miscellaneous
    # ===========================================
    HashType(
        mode=12001,
        name="Atlassian (PBKDF2-HMAC-SHA1)",
        example="{PKCS5S2}byA77oLTm...",
        pattern=r"^\{PKCS5S2\}",
        prefix="{PKCS5S2}",
        category="Enterprise"
    ),
    HashType(
        mode=101,
        name="nsldap, SHA-1(Base64), Netscape LDAP SHA",
        example="{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=",
        pattern=r"^\{SHA\}[A-Za-z0-9+/=]+$",
        prefix="{SHA}",
        category="LDAP"
    ),
    HashType(
        mode=111,
        name="nsldaps, SSHA-1(Base64), Netscape LDAP SSHA",
        example="{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng==",
        pattern=r"^\{SSHA\}[A-Za-z0-9+/=]+$",
        prefix="{SSHA}",
        category="LDAP"
    ),
    HashType(
        mode=1411,
        name="SSHA-256(Base64), LDAP {SSHA256}",
        example="{SSHA256}OZiz...",
        pattern=r"^\{SSHA256\}",
        prefix="{SSHA256}",
        category="LDAP"
    ),
    HashType(
        mode=1711,
        name="SSHA-512(Base64), LDAP {SSHA512}",
        example="{SSHA512}ALtwKGBdRg...",
        pattern=r"^\{SSHA512\}",
        prefix="{SSHA512}",
        category="LDAP"
    ),
    HashType(
        mode=16500,
        name="JWT (JSON Web Token)",
        example="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.L8i6g3PfcHlioHCCPURC9pmXT7gdJpx3kOoyAfNUwCc",
        pattern=r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$",
        prefix="eyJ",
        category="Web"
    ),
]


def identify_hash_type(hash_string: str) -> List[HashType]:
    """
    Identify possible hash types for a given hash string.

    Args:
        hash_string: The hash to identify

    Returns:
        List of matching HashType objects, ordered by likelihood
    """
    matches = []

    for hash_type in HASH_TYPES:
        # Check by prefix first (fastest)
        if hash_type.prefix and not hash_string.startswith(hash_type.prefix):
            continue

        # Check by length if specified
        if hash_type.length and len(hash_string) != hash_type.length:
            continue

        # Check pattern match
        if re.match(hash_type.pattern, hash_string):
            matches.append(hash_type)

    return matches


def get_most_likely_type(hash_string: str) -> Optional[HashType]:
    """
    Get the most likely hash type for a given hash.

    Prioritizes:
    1. Hashes with specific prefixes (most reliable)
    2. Longer hashes (more specific)
    3. NTLM for 32-char hex (most common in password cracking)

    Args:
        hash_string: The hash to identify

    Returns:
        Most likely HashType or None if no match
    """
    matches = identify_hash_type(hash_string)

    if not matches:
        return None

    if len(matches) == 1:
        return matches[0]

    # Prioritize by prefix (most specific)
    prefix_matches = [m for m in matches if m.prefix]
    if prefix_matches:
        return prefix_matches[0]

    # For 32-char hex, prefer NTLM (most common in password cracking scenarios)
    if len(hash_string) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_string):
        for m in matches:
            if m.mode == 1000:  # NTLM
                return m

    # Return first match
    return matches[0]


def categorize_potfile_hashes(entries: List[Tuple[str, str]]) -> dict:
    """
    Categorize hashes from a potfile by their type.

    Args:
        entries: List of (hash, password) tuples

    Returns:
        Dictionary with hash type statistics:
        {
            "ntlm": {"count": 100, "mode": 1000, "name": "NTLM"},
            "md5": {"count": 50, "mode": 0, "name": "MD5"},
            "unknown": {"count": 10, "mode": None, "name": "Unknown"},
            ...
        }
    """
    stats = {}

    for hash_str, _ in entries:
        hash_type = get_most_likely_type(hash_str)

        if hash_type:
            key = hash_type.name.lower().replace(" ", "_").replace("-", "_")
            if key not in stats:
                stats[key] = {
                    "count": 0,
                    "mode": hash_type.mode,
                    "name": hash_type.name,
                    "category": hash_type.category
                }
            stats[key]["count"] += 1
        else:
            if "unknown" not in stats:
                stats["unknown"] = {
                    "count": 0,
                    "mode": None,
                    "name": "Unknown",
                    "category": "Unknown"
                }
            stats["unknown"]["count"] += 1

    return stats


def is_ntlm_hash(hash_string: str) -> bool:
    """
    Check if a hash string is a valid NTLM hash format.

    Args:
        hash_string: The hash to check

    Returns:
        True if it matches NTLM format (32 hex chars)
    """
    return bool(re.match(r'^[a-fA-F0-9]{32}$', hash_string))


def get_hash_type_summary() -> dict:
    """
    Get a summary of all supported hash types by category.

    Returns:
        Dictionary mapping categories to lists of hash type info
    """
    summary = {}

    for hash_type in HASH_TYPES:
        if hash_type.category not in summary:
            summary[hash_type.category] = []
        summary[hash_type.category].append({
            "mode": hash_type.mode,
            "name": hash_type.name,
            "example": hash_type.example[:50] + "..." if len(hash_type.example) > 50 else hash_type.example
        })

    return summary
