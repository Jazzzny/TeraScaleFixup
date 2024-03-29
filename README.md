# TeraScaleFixup
Lilu plugin for unsupported AMD TeraScale GPUs on macOS - a modern, OpenCore-centric approach to the QE_CI Exotic Patch

## Supported GPUs
<table>
    <thead>
        <tr>
            <th colspan=3>ATI Radeon HD 4xxx</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Name</td>
            <td>Notes</td>
        </tr>
        <tr>
            <td>HD 4350</td>
            <td></td>
        </tr>
        <tr>
            <td>HD 4550</td>
            <td></td>
        </tr>
        <tr>
            <td>HD 4570</td>
            <td></td>
        </tr>
        <tr>
            <td>HD 4650</td>
            <td></td>
        </tr>
        <tr>
            <td>HD 4770</td>
            <td></td>
        </tr>
        <tr>
            <td>HD 4830</td>
            <td></td>
        </tr>
        <tr>
            <td>HD 4850</td>
            <td></td>
        </tr>
        <tr>
            <td>HD 4870x2</td>
            <td>Only 1 GPU chip will be used</td>
        </tr>
        <tr>
            <td>HD 4890</td>
            <td></td>
        </tr>
    </tbody>
</table>

**NOTE:** VGA & DVI->VGA outputs are not natively supported. You must [manually patch the AMD framebuffer](https://www.tonymacx86.com/threads/guide-how-to-patch-amd-framebuffers-for-high-sierra-using-clover.235409/).

## macOS Compatibility
All "final release" versions of macOS from 10.7-10.13 are supported. This includes:
- 10.7.5 (11G63)
- 10.8.5 (12F2560)
- 10.9.5 (13F1911)
- 10.10.5 (14F2511)
- 10.11.6 (15G22010)
- 10.12.6 (16G2136)
- 10.13.6 (17G14042)

**NOTE 1:** Newer releases may function by using OpenCore Legacy Patcher.

**NOTE 2:** Installing this kext on 10.5 or 10.6 should enable acceleration through IOKitPersonalities injection.

## Installation
- Lilu must be installed alongside this kext for proper functionality; the latest release is recommended.