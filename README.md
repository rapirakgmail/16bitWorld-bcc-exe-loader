# BCC-exe loader
# รายละเอียด
    - วัตถุประสงค์เพื่อเสริมความเข้าใจเกี่ยวกับกลไกลการทำงานของ loader module ของระบบปฎิบัติการ DOS
    - โปรแกรมรองรับเฉพาะระบบปฎิบัติการ DOS 16 bit และ DOXBOX
    - โปรแกรมรองรับเฉพาะการโหลดแฟ้ม ".EXE" เท่านั้น
    - พัฒนาโดยใช้  compiler ของ Borland C (3.x)   

# แฟ้ม
      1. LOADMZ.C  : source file ของโปรแกรม  exe loader
             การ compile
             bcc LOADMZ.C    (ได้ LOADMZ.exe)
             
      2. MZ.C  : source file ของ  exe ของโปรแกรมแสดง ".EXE" header info
             การ compile
             bcc MZ.C      (ได้ MZ.exe)
      
      3. H.C : source file ของโปรแกรมตัวอย่าง
            การ compile
            bcc [-mt | -ms | -ml | -mh] H.C     (ได้ H.EXE)
            -mt : tinny model 
            -ms : small model * default option  
            -ml large mode 
            -mh hurge model
      4. MZ.ZIP : zip file ที่มีการ compile สำเร็จแล้ว
          โดย ht.exe , hs.exe , hl.exe , hl.exe คือโปรแกรม h.c ที่ถูก compile ด้วย model option แบบต่างๆ 
          
 # การใช้งาน LOADMZ.EXE
     loadmz c:\mz\ht.exe   โหลดโปรแกรม ht.exe มา run
     
 # การใช้งาน MZ.EXE
     mz c:\mz\ht.exe   แสดง exe header ของ โปรแกรม ht.exe มา run

# การสร้าง enviroment ในการสร้รงโปรแกรม
    สามารถดูได้จาก
      https://github.com/rapirakgmail/16bitWorld-bcc-env/edit/main/README.md
