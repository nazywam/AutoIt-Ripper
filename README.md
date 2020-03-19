# AutoIt-Ripper

## What is this
This is a (semi) short python script that allows for extraction of "compiled" AutoIt scripts from PE executables.

## References
This script **heavily** bases on 2 resources, definitely check them out if you want to dig a bit deeper into the whole AutoIt stuff:
 * http://files.planet-dl.org/Cw2k/MyAutToExe/index.html
   * [Github mirror I](https://github.com/dzzie/myaut_contrib)
   * [Github mirror II](https://github.com/PonyPC/myaut_contrib)
 * https://github.com/sujuhu/autoit

## Support versions

### Ready:

* `EA06` AutoIt3.26++

### Planned:

* `EA05` AutoIt3.00

### Unknown:

* `JB01` AutoHotKey
* `JB01` AutoIT2

## Installation
```bash
python3 -m pip install -r requirements.txt
```

## Running
```bash
python3 main.py input.exe
```

![](img/smoke.png)


## Format documentation
#### (In progress)


### AU3 header

|    Field   |    Length    |     LAME seed     |            Notes            |
|:----------:|:------------:|:-----------------:|:---------------------------:|
|   "FILE"   |       4      |       0x18EE      |        static string        |
|    flag    |       4      |       0xADBC      |                             |
|  auto_str  |   flag * 2   |   0xB33F + flag   |            UTF-16           |
|  path_len  |       4      |       0xF820      |                             |
|    path    | path_len * 2 | 0xF479 + path_len | Path of the compiled script |
| compressed |       1      |        None       |                             |
|  data_size |       4      |       0x87BC      |      encoded data size      |
|  code_size |       4      |       0x87BC      |   TODO: actual use of this  |
|     crc    |       4      |       0xA685      |    uncompressed data hash   |
|   unknown  |      16      |        None       |                             |
|    data    |   data_size  |       0x2477      |         script data         |
