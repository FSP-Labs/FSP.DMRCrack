// FSP.DMRCrack - GPU-accelerated ARC4 key recovery for DMR communications
// Copyright (C) 2026 FSP-Labs
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see https://www.gnu.org/licenses/.

#ifndef VERSION_H
#define VERSION_H

#define DMRCRACK_VERSION       "0.1.0"
#define DMRCRACK_VERSION_MAJOR  0
#define DMRCRACK_VERSION_MINOR  1
#define DMRCRACK_VERSION_PATCH  0

/* Wide-string version for WinSparkle API */
#define WIDE_(x) L##x
#define WIDE(x)  WIDE_(x)
#define DMRCRACK_VERSION_W  WIDE(DMRCRACK_VERSION)

/* GitHub repository coordinates */
#define DMRCRACK_GITHUB_OWNER  "FSP-Labs"
#define DMRCRACK_GITHUB_REPO   "FSP.DMRCrack"

/* WinSparkle appcast URL (hosted as a GitHub Release asset on the 'appcast' tag) */
#define DMRCRACK_APPCAST_URL \
    "https://github.com/" DMRCRACK_GITHUB_OWNER "/" DMRCRACK_GITHUB_REPO \
    "/releases/download/appcast/appcast.xml"

/* EdDSA (Ed25519) public key for update signature verification.
 * Generated with: winsparkle-tool generate-key
 * The corresponding private key must be stored as a GitHub Actions secret
 * (WINSPARKLE_EDDSA_PRIVATE_KEY) and NEVER committed to the repository. */
#define DMRCRACK_EDDSA_PUB_KEY  "eB8+6/FIXwTcE7iESdVD/aepKpM5z6NdA9Au5N4oStg="

#endif /* VERSION_H */
