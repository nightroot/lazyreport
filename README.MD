# lazyreport使用
## 内容
``` python3
# 收集极光扫描器域Nessus扫描器所有中危及以上漏洞信息（包含脆弱性账号）
```
## 模式&参数
### --auto 自动模式
```
--auto 自动模式
无需任何参数，自动检测当前文件夹下的极光扫描zip文件和nessus扫描html文件
极光扫描文件需要综述报表与主机报表一起导出
nessus扫描文件是plugin导出的标准文件

示例
python3 ./lazyreport --auto
```
### 手动模式
```
-a --afile      绿盟极光导出zip文件名
-n --nfile      nessus扫描文件plugin导出文件名

示例
python3 .\lazyreport.py -a 1883XX工程项目_2019_11_01_html.zip -n XX工程项目plugin.html
```