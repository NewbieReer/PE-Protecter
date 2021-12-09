#include<stdio.h>
#include<windows.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"aplib.lib")
#include"aplib.h"

struct Addr_Trans {
    DWORD VirtualAddress;
    DWORD PointerToRawData;
    DWORD VirtualSize;
    DWORD SizeOfRawData;
    Addr_Trans * Prev;
};

#define RBEGIN(S,...) printf("Reading "#S"...\n",__VA_ARGS__);
#define RDONE(S,...) printf(#S" read.\n",__VA_ARGS__);
#define PPRE printf("\033[1;34;40m[*]\033[0m ");
#define RPRE printf("\033[1;32;40m[+]\033[0m ");
#define RIPRE RPRE
#define WPRE printf("\033[1;31;40m[-]\033[0m ");
#define WROPRE WPRE
#define REMARK(S,...) printf(" \033[1;36;40m//"#S"\033[0m",__VA_ARGS__);
#define NL   printf("\n");
#define INFO(S,...) printf("\033[1;33;40m====================About "#S"====================\033[0m\n",__VA_ARGS__);

UINT    m_nImageSize = 0;
PIMAGE_NT_HEADERS   m_pNtHeaders = NULL;
PIMAGE_SECTION_HEADER   m_pSecHeader = NULL;        //第一个section结构指针
PCHAR   m_pImageBase = 0;
Addr_Trans* lnk_Addr_Trans = new Addr_Trans();
//For packing
PCHAR m_pPackData = NULL;
int m_nPackSize = 0;

DWORD RVAToPtr(DWORD addr) {
   //我晕，这个好像是转化为我们手动加载到内存里面的地址的函数
    //一直理解成了RVAToRAW，ai
    return addr + (DWORD)m_pImageBase;
}

DWORD RVAToRAW(DWORD addr) {
    //​ RAW = RVA - VirtualAddress + PointerToRawData
    //【PointerToRawData】以及【VirtualAddress】，在上式中表示的是在【IMAGE_SECTION_HEADER结构体】里的字段
    //指的是【磁盘文件中节区起始地址】以及【内存中节区起始地址】
    if (lnk_Addr_Trans->Prev == NULL) {
        WROPRE printf("Section Trans Form hasn't been Inited.\n");
        throw "Section Trans Form hasn't been Inited.\n";
        return NULL;
    }
    else {
        for (Addr_Trans* lnk_Addr_Trans_tmp = lnk_Addr_Trans->Prev; lnk_Addr_Trans_tmp != NULL; lnk_Addr_Trans_tmp = lnk_Addr_Trans_tmp->Prev) {
            if ((int)addr <= (int)(lnk_Addr_Trans_tmp->VirtualAddress + lnk_Addr_Trans_tmp->VirtualSize) && (int)addr >= (int)(lnk_Addr_Trans_tmp->VirtualAddress)) {
                printf("va = %d, va + sz = %d, addr = %d\n", lnk_Addr_Trans_tmp->VirtualAddress, lnk_Addr_Trans_tmp->VirtualAddress + lnk_Addr_Trans_tmp->VirtualSize, addr);
                return addr - lnk_Addr_Trans_tmp->VirtualAddress + lnk_Addr_Trans_tmp->PointerToRawData;
            }
        }
    }
    return NULL;
}

/*-------------------------------------------------------------
 AddPackInfo
记录压缩过的区块信息，用于外壳在运行时解压缩
数据储存格式：
DWORD  保存区块原大小_解压所需空间大小
DWORD  保存区块原偏移_解压起点
DWORD  保存压缩后大小_解压数量

以后会保存在shell.asm变量：
S_PackSection	DB	0a0h dup (?)
-------------------------------------------------------------*/

BOOL AddPackInfo(UINT OriginalOffset, UINT OriginalSize, UINT nPackSize)
{
    UINT m_pInfoSize = 0;
    const UINT SIZE_OF_PACKINFO = 0x2000;
    PCHAR m_pInfoData = new CHAR[SIZE_OF_PACKINFO];
    try
    {
        if (m_pInfoData == NULL)
        {
            WROPRE printf("无效的参数\n");
            return FALSE;
        }

        if (m_pInfoSize + sizeof(UINT) * 2 > SIZE_OF_PACKINFO)
        {
            WROPRE printf("缓冲区申请空间太小");
            return FALSE;
        }


        *(UINT*)(&m_pInfoData[m_pInfoSize]) = OriginalSize;//保存区块原大小_解压所需空间大小
        m_pInfoSize += sizeof(UINT);

        //保存区块原偏移_解压起点
        *(UINT*)(&m_pInfoData[m_pInfoSize]) = OriginalOffset;
        m_pInfoSize += sizeof(UINT);

        //记录压缩数据大小
        *(UINT*)(&m_pInfoData[m_pInfoSize]) = nPackSize;
        m_pInfoSize += sizeof(UINT);
    }
    catch (...)     //这是什么用法？
    {
        WROPRE printf("未知异常");
        return FALSE;
    }

    return TRUE;
}
//进行区块融合
BOOL MergeSection() {
    UINT nSectionNum = 0;
    PIMAGE_SECTION_HEADER psecHeader = m_pSecHeader;
    UINT nspareSize = NULL;
    UINT nMergeVirtualSize = 0;
    UINT nIndex = 0;
    
    nSectionNum = m_pNtHeaders->FileHeader.NumberOfSections;
    for (nIndex = 0; nIndex < nSectionNum; nIndex++, psecHeader++) {
        if ((m_pSecHeader->Characteristics & IMAGE_SCN_MEM_SHARED) != 0)    //这里的共享区块是什么
            break;
        if(strcmp((char*)psecHeader->Name,".edata") == 0)
            break;
        if (strcmp((char*)psecHeader->Name, ".rsrc") == 0)
            break;
        nMergeVirtualSize += psecHeader->Misc.VirtualSize;  //这个字段的PhysicalAddress为什么没有用过？
    }
    m_pSecHeader->Misc.VirtualSize = nMergeVirtualSize;
    m_pNtHeaders->FileHeader.NumberOfSections = nSectionNum - nIndex + 1;   //-nIndex是减去被合并的区块数，+1是因为这些区块合并成为了一个
    
    memcpy(m_pSecHeader + 1, psecHeader, (nSectionNum - nIndex) * sizeof(IMAGE_SECTION_HEADER));
    nspareSize = (nSectionNum - m_pNtHeaders->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER); //合并节区头余出来的节区头空间
    memset(m_pSecHeader + nSectionNum - nIndex + 1, 0, nspareSize);
}

BOOL IsSectionCanPacked(PIMAGE_SECTION_HEADER psecHeader)
{
    //	ASSERT(psecHeader != NULL);

    UINT  nExportAddress = 0;
    const UINT	nListNum = 6;
    const char * lpszSecNameList[nListNum] =
    {
        ".text",
        ".data",
        ".rdata",
        "CODE",
        "DATA",
        ".reloc",
    };
    //导出表的地址
    nExportAddress = m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;


    // 如果发现匹配的区块名称，则表示此区块可以压缩
    for (UINT nIndex = 0; nIndex < nListNum; nIndex++)
    {
        //导出表不可以被压缩
        //有些输出表可能会在.rdata等区块，如果区块合并了就不能这样判断了
        // EXE文件里很少有导出表，tls所在的地方是tls table，但是IDA判断它是导出表，神奇
//        if (!IsMergeSection)
        {
            if ((nExportAddress >= psecHeader->VirtualAddress) && (nExportAddress < (psecHeader->VirtualAddress + psecHeader->Misc.VirtualSize)))
                return FALSE;
        }

        if (strncmp((char*)psecHeader->Name, lpszSecNameList[nIndex], strlen(lpszSecNameList[nIndex])) == 0)
        {
            return TRUE;
        }
    }

    // 否则其他区块都不能压缩
    return FALSE;
}

UINT MoveImpTable(PCHAR m_pImportTable) {   //这里是输入,新输入表的地址
    //处理输入表
    //下面的代码将输入表以另一种形式存储

    PIMAGE_IMPORT_DESCRIPTOR pIID = NULL, pIID_tmp = NULL;
    PIMAGE_DATA_DIRECTORY pImportDir = NULL;    //optional的最后一项，那个数组中的元素
    PCHAR pData = NULL;
    PCHAR pDllName = NULL;
    PCHAR pFunNum = NULL;
    PIMAGE_THUNK_DATA32 pFirstThunk = NULL;
    PIMAGE_IMPORT_BY_NAME pImportByName = NULL;

    //IID结构体数组不在PE头，而在PE体中（注意下面两行代码写法）
    pImportDir = &m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];//-> . []属于同一优先级，自左向右，&优先级比他们小
    //RVAToPtr函数的作用是获得文件中的偏移
    try {
        pIID = (PIMAGE_IMPORT_DESCRIPTOR)RVAToPtr(pImportDir->VirtualAddress);
    }
    catch (const char* msg) {
        printf(msg);
        return (int)false;
    }
    //printf("@%x\n", *pImportDir);//*pImportDir取的是第一个字段的内容，也就是VirtualAddress变量的内容，储存的是IID数组的RVA。pImportDir指向的不是IID而是IMAGE_DATA_DIRECTORY，要搞清楚
    //printf("#%x\n", pIID);//这里如果*pIID的话是IID第一个字段的内容，会引发读异常
    PPRE printf("Start to dump IID...\n");
    //printf("%p\n", pImportDir);
    //printf("%p\n", pIID);
    
    char InfoSwitch = 0;

    for (pData = m_pImportTable, pIID_tmp = pIID; pIID_tmp->Name != 0; pIID_tmp++) {
        *(DWORD*)pData = pIID_tmp->FirstThunk;
        pData += sizeof(DWORD);     //先存第一个thunk的RVA

        pDllName = (PCHAR)RVAToPtr(pIID_tmp->Name);
        *(BYTE*)(pData) = (BYTE)(strlen(pDllName) + 1);
        pData += sizeof(BYTE);//再存DLL名字的长度

        memcpy(pData, pDllName, strlen(pDllName) + 1);//再把DLL名字存入
        pData += strlen(pDllName) + 1;

        pFunNum = pData;
        *(DWORD*)pFunNum = 0;//初始化函数的数目
        pData += sizeof(DWORD);
        //这里处理32位的程序
        //pFirstThunk存的是OriginalFirstThunk或者FirstThunk的值，具体可以看博客
        
        INFO(% s, pDllName);
        printf("Input y to show This DLL's imported function.\n");
        InfoSwitch = getchar();
        
        printf("Addr of FirstThink: 0x%08x", pIID_tmp->FirstThunk);
        NL;


        if (pIID_tmp->OriginalFirstThunk != 0) {
            pFirstThunk = (PIMAGE_THUNK_DATA32)RVAToPtr(pIID_tmp->OriginalFirstThunk);
        }
        else {
            pFirstThunk = (PIMAGE_THUNK_DATA32)RVAToPtr(pIID_tmp->FirstThunk);
        }
        while (pFirstThunk->u1.AddressOfData != NULL) {
            if (IMAGE_SNAP_BY_ORDINAL32(pFirstThunk->u1.Ordinal)) {    //这个函数判断最高位是不是1
                                                                       //为1的时候函数以序列号方式输入
                                                                       //为0的时候函数以字符串类型输入
                                                                       //函数通过序号导出的     0 序号 ? | 0 序号 ? |...
                *(BYTE*)pData = 0;     //这里为什么置零的
                pData += sizeof(BYTE);
                *(DWORD*)pData = (DWORD)(pFirstThunk->u1.Ordinal & 0x7FFFFFFF); //填上序号
                if (InfoSwitch == 'y') {
                    printf("BY Ordinal: %08x", pData);
                    NL;
                }
                pData += sizeof(DWORD) + 1;
                (*(DWORD*)pFunNum)++;

            }
            else {  //函数通过名字导出的                     len name | len name | ...
                pImportByName = (PIMAGE_IMPORT_BY_NAME)RVAToPtr((DWORD)(pFirstThunk->u1.AddressOfData));//HINT/NAME结构，NAME需要取一下位置
                *(BYTE*)pData = (BYTE)(strlen((char*)pImportByName->Name) + 1); //存储名字的长度
                pData += sizeof(BYTE);
                memcpy(pData, pImportByName->Name, strlen((char*)pImportByName->Name) + 1);
                if (InfoSwitch == 'y') {
                    printf("BY Name: %s", pData);
                    NL;
                }
                pData += strlen((char*)pImportByName->Name + 1);
                (*(DWORD*)pFunNum)++;
            }
            pFirstThunk++;
        }
        InfoSwitch = 0;
        RIPRE printf("Num of Function: %d", *pFunNum);
        NL;
    }
    RIPRE printf("IID dumped.\n");
    NL;
    *(DWORD*)pData = (DWORD)0;  //结束标志
    pData += sizeof(DWORD);
    return pData - m_pImportTable;  //新的ImportTable的长度
}

void CleanImpTable() {
    //下面对原输入表清理
    PIMAGE_IMPORT_DESCRIPTOR pIID_tmp = NULL, pIID = (PIMAGE_IMPORT_DESCRIPTOR)RVAToPtr((DWORD)m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    PCHAR pDllName = NULL;
    PIMAGE_THUNK_DATA32 pFirstThunk = NULL;
    PIMAGE_IMPORT_BY_NAME pImportByName = NULL;

    PPRE printf("Start to clean import table...\n");

    for (pIID_tmp = pIID; pIID_tmp->ForwarderChain != 0; pIID_tmp++) {
        pDllName = (PCHAR)RVAToPtr(pIID_tmp->Name);
        printf("%s", pDllName);
        memset(pDllName, 0, strlen(pDllName));      //DLL名称所在的地址
        if (pIID_tmp->OriginalFirstThunk != NULL) {
            pFirstThunk = (PIMAGE_THUNK_DATA32)RVAToPtr(pIID_tmp->OriginalFirstThunk);
            while (pFirstThunk->u1.Function != NULL) {   //thunkdata以全零的IMAGE_THUNK_DATA结尾
                //这里记得处理一下序号导入方式的函数
                if (IMAGE_SNAP_BY_ORDINAL32(pFirstThunk->u1.Ordinal)) {
                    memset(pFirstThunk, 0, sizeof(DWORD));
                }
                else {
                    pImportByName = (PIMAGE_IMPORT_BY_NAME)RVAToPtr(pFirstThunk->u1.AddressOfData);
                    memset(pImportByName, 0, sizeof(WORD)); //先清hint
                    //printf("%s", &pImportByName->Name);
                    //getchar();
                    memset(&pImportByName->Name, 0, strlen(pImportByName->Name));   //清理后面直接跟着的NAME数组
                }
                pFirstThunk++;
            }
        }

        //清除FirstThunk
        pFirstThunk = (PIMAGE_THUNK_DATA32)RVAToPtr(pIID_tmp->FirstThunk);
        while (pFirstThunk->u1.AddressOfData != NULL) {
            memset(pFirstThunk, 0, sizeof(DWORD));
            pFirstThunk++;
        }
        memset(pIID_tmp, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));//整个IID清零
    }
    RIPRE printf("improt table has been cleaned.\n");
    NL;
}

void ClsRelocData() {
    //处理重定位表
    //这里按理说为了提高强度应该转储以下重定位表的，比较懒，之后再说
    PIMAGE_BASE_RELOCATION pBaseReloc = NULL;
    PIMAGE_DATA_DIRECTORY pRelocDir = NULL;
    UINT nSize = 0;
    DWORD nbWitten = 0;
    int nNewSize;
    
    PPRE printf("Start to clean the reloc table...\n");
    pRelocDir = &m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    pBaseReloc = (PIMAGE_BASE_RELOCATION)RVAToPtr(pRelocDir->VirtualAddress);       //重定位表的地址
    if (pRelocDir->VirtualAddress == NULL) {
        PPRE printf("No reloc data has been found.\n");
        NL;
        return; //如果没有重定位数据
    }
    //清除重定位数据
    //所有重定位块以一个VirtualAddress字段为0的IMAGE_BASE_RELOCATION结构结束
    
    while (pBaseReloc->VirtualAddress != NULL) {
        nSize = pBaseReloc->SizeOfBlock;
        memset(pBaseReloc, 0, nSize);
        pBaseReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseReloc + nSize);   //下一个IMAGE_BASE_RELOCATION
    }
    RIPRE printf("Reloc table has been cleaned.\n");
    m_pNtHeaders->OptionalHeader.DataDirectory[5].VirtualAddress = 0;
    m_pNtHeaders->OptionalHeader.DataDirectory[5].Size = 0;
    RIPRE printf("Reloc DataDirectory has been cleaned.\n");
    NL;
}

UINT AlignSize(UINT nSize, UINT nAlign)             //取整对齐函数
{
    return ((nSize + nAlign - 1) / nAlign * nAlign);
}

void FillZero(HANDLE hFile, UINT nLength)
{
    CHAR	ch = 0;
    DWORD   nbWritten;

    while (nLength-- > 0)
    {
        WriteFile(hFile, &ch, 1, &nbWritten, NULL);
    }
}
BOOL PackData(PCHAR pData, UINT nSize) {        //第一个参数是需要pack的地址，第二个参数是大小
    PCHAR pCloneData = NULL;
    UINT m_nSpaceSize = NULL;

    m_nSpaceSize = aP_workmem_size(nSize);              //计算所需要的工作空间大小
    PCHAR m_pWorkSpace = new CHAR[m_nSpaceSize];        //临时工作空间申请
    m_pPackData = new CHAR[nSize * 2];      //申请两倍的空间可能是害怕放不下吧，但是为tm什么压缩后会有可能大于两倍啊？
    //m_pPackData指的是压缩之后数据所在的地方
    pCloneData = (PCHAR)GlobalAlloc(GMEM_FIXED, nSize); //原始数据放到新的空间中进行备份

    memcpy(pCloneData, pData, nSize);
    RIPRE printf("Start packing...\n");
    m_nPackSize = aP_pack((PBYTE)pCloneData, (PBYTE)m_pPackData, nSize, (PBYTE)m_pWorkSpace, 0, 0);

    if (m_nPackSize == APLIB_ERROR) {
        WROPRE printf("Error during packing...\n");
        return false;
    }
    RIPRE printf("Packing done.\n");
    GlobalFree(pCloneData);
    pCloneData = NULL;

    return true;
}

UINT CalcMinSizeOfData(PCHAR pData, UINT nSize){
    PCHAR pEndData = pData + nSize;
    
    while (*pEndData != 0) {
        pEndData--;
    }

    return pEndData - pData;
}

UINT FindFirstResADDR() {
    //为什么有些类型的资源不能压缩——因为这些资源在程序没有运行的情况下也可能被系统读取和使用
//比如查看文件夹的内容时，目录下的所有应用程序图标都会显示出来。这些图标是程序资源的一部分，在程序没有
//执行的时候仍然会被系统读取。
//通常包括ICON、Group Icon、Version Information等，见16种标准类型。
//轻则程序异常(丢失图标)，重则导致程序无法运行。
//而且系统必须通过资源目录才能找到它们，所以资源目录也不能被压缩。
    UINT    FirstResAddr = NULL;
    PIMAGE_DATA_DIRECTORY pResourceDir = NULL;
    PIMAGE_RESOURCE_DIRECTORY pResource = NULL;
    PIMAGE_RESOURCE_DIRECTORY pTypeRes = NULL;
    int nTypeNum = 0;
    int nTypeIndex = 0;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pTypeEntry = NULL;
    PIMAGE_RESOURCE_DIRECTORY pNameIdRes = NULL;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pNameIdEntry = NULL;
    int nNameIdNum;
    PIMAGE_RESOURCE_DIRECTORY pLanguageRes = NULL;
    int nLanguageNum = 0;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pLanguageEntry = NULL;
    int nNameIdIndex = 0;
    int nLanguageIndex = 0;
    PIMAGE_RESOURCE_DATA_ENTRY pResData = NULL;

    FirstResAddr = m_pNtHeaders->OptionalHeader.SizeOfImage;
    pResourceDir = &m_pNtHeaders->OptionalHeader.DataDirectory[2];
    if (pResourceDir->VirtualAddress = NULL)     //没有资源的情况
        return FALSE;
    pResource = (PIMAGE_RESOURCE_DIRECTORY)RVAToPtr(pResourceDir->VirtualAddress);
    //注:TypeRes是第一级目录，资源类型
    //  NameIdRes是第二级目录，资源ID比如菜单IDM_OPEN的ID号，IDM_EXIT的ID号
    //LanguageRes是第三级目录
    pTypeRes = pResource;
    nTypeNum = pTypeRes->NumberOfIdEntries + pTypeRes->NumberOfNamedEntries;
    pTypeEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pTypeRes + sizeof(IMAGE_RESOURCE_DIRECTORY));//资源目录头下面第一个资源目录项地址

    for (nTypeIndex = 0; nTypeIndex < nTypeNum; nTypeIndex++, pTypeEntry++) {
        //注意OffsetToDirectory是相对于资源表起始位置的
        //下面这个是下一级目录的地址了
        pNameIdRes = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResource + (DWORD)pTypeEntry->OffsetToDirectory);
        nNameIdNum = pNameIdRes->NumberOfIdEntries + pNameIdRes->NumberOfNamedEntries;
        //这是第三级目录了
        pNameIdEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pNameIdRes + sizeof(IMAGE_RESOURCE_DIRECTORY));

        for (nNameIdIndex = 0; nNameIdIndex < nNameIdNum; nNameIdIndex++, pNameIdEntry++) {
            pLanguageRes = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResource + (DWORD)pNameIdEntry->OffsetToDirectory);
            nLanguageNum = pLanguageRes->NumberOfIdEntries + pLanguageRes->NumberOfNamedEntries;
            pLanguageEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pLanguageRes + sizeof(PIMAGE_RESOURCE_DIRECTORY));

            for (nLanguageIndex = 0; nLanguageIndex < nLanguageNum; nLanguageIndex++, pLanguageEntry++) {
                pResData = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pResource + pLanguageEntry->OffsetToData);
                if ((pResData->OffsetToData < FirstResAddr) && (pResData->OffsetToData > pResourceDir->VirtualAddress)) {
                    FirstResAddr = pResData->OffsetToData;
                }
            }
        }
    }
    //FirstResAddr保存着分界数据
    return FirstResAddr;
}


BOOL PackFile(TCHAR* szFilePath) {
    bool isPackRes = true;
    bool flag;
    DWORD NumberOfBytes = NULL;
    PPRE RBEGIN(File for packing);
    //文件的压缩
    PIMAGE_DATA_DIRECTORY pResourceDir = NULL;
    UINT nResourceDirSize = NULL;
    PCHAR pResourcePtr = NULL;
    UINT nResourceSize;
    UINT nRawSize = 0;
    PCHAR pDataForPack = NULL;
    HANDLE hPackFile = CreateFile(szFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hPackFile == INVALID_HANDLE_VALUE) {
        WROPRE printf("Error in reading file for packing\n");
        return (int)false;
    }
    UINT nSectionNum = m_pNtHeaders->FileHeader.NumberOfSections;
    UINT nFileAlign = m_pNtHeaders->OptionalHeader.FileAlignment;
    UINT nSectionAlign = m_pNtHeaders->OptionalHeader.SectionAlignment;
    PIMAGE_SECTION_HEADER pSecHeader = m_pSecHeader;
    //重新计算PE头大小，考虑增加一个节区，注意数组下标从0开始
    UINT nSize = (PCHAR)(&pSecHeader[nSectionNum + 1]) - m_pImageBase;
    unsigned int nIndex = 0;
    UINT nNewSize;

    nSize = AlignSize(nSize, nFileAlign);
    //将PE头大小字段改掉
    m_pNtHeaders->OptionalHeader.SizeOfHeaders = nSize;
    m_pSecHeader->PointerToRawData = nSize;     //因为添加了一个节区，节区头发生了变化，因此第一个节区的地址也被改变了
    pSecHeader = m_pSecHeader;
    //https://blog.csdn.net/zjhkobe/article/details/7687692
    PPRE printf("Writing header...\n");
    flag = WriteFile(hPackFile, m_pImageBase, nSize, &NumberOfBytes, NULL);
    //注意After the write operation has been completed
    //the file pointer is adjusted by the number of bytes written.
    //所以下一个writefile是接着写
    if (flag == false) {
        WROPRE printf("Error in writing header.\n");
        return (int)false;
    }
    RIPRE printf("Header has been written\n");
    NL;
    PPRE printf("Writing Section...\n");
    for (nIndex = 0; nIndex < nSectionNum; nIndex++, pSecHeader++) {
        pDataForPack = (PCHAR)RVAToPtr(pSecHeader->VirtualAddress);
        nSize = pSecHeader->Misc.VirtualSize;
        PPRE printf("Dealing with Section %s", pSecHeader->Name);
        
        nNewSize = CalcMinSizeOfData(pDataForPack, nSize);      //因为前面的一些操作，导致某些区块的部分数据已经被清除，可能导致区块变小
        //这里通过搜索并清除尾部无用的0字节来重新计算区块大小    这个函数自己实现的
        
        if (nNewSize == 0) {
            pSecHeader->SizeOfRawData = 0;
            pSecHeader->Characteristics |= IMAGE_SCN_MEM_WRITE; //为什么这里要给写属性
            if (nIndex != nSectionNum - 1) {
                (pSecHeader + 1)->PointerToRawData = pSecHeader->PointerToRawData + pSecHeader->SizeOfRawData;
                //这里调整了本区块的大小，因为这里已经是0了，所以本区的SizeOfRawData为0，修改下一个区块的指针。
            }
            continue;
        }
        if (IsSectionCanPacked(pSecHeader)) {   //这个函数由书中提供
            PackData(pDataForPack, nNewSize);
            nRawSize = AlignSize(m_nPackSize, nFileAlign);
            flag = WriteFile(hPackFile, (PCHAR)m_pPackData, m_nPackSize, &NumberOfBytes, NULL);
            if (flag == false) {
                WROPRE printf("Error in writing with section %s.\n", pSecHeader->Name);
                return (int)false;
            }
            if (nRawSize - m_nPackSize > 0) {
                FillZero(hPackFile, nRawSize - m_nPackSize);//起初以为传入的句柄就是一个地址，然后发现报错
            }                                                       //现在才知道这个句柄不能简单的认为是地址
            pSecHeader->SizeOfRawData = nRawSize;
            //下面的函数用来记录压缩后的节区信息，用于外壳运行时解压缩
            AddPackInfo(pSecHeader->VirtualAddress, pSecHeader->Misc.VirtualSize, pSecHeader->SizeOfRawData);
        }
        else {
            if ((strcmp((char*)pSecHeader->Name, ".rsrc") == 0) && isPackRes) { //这个变量是对话框里选择是否压缩资源的
                pResourceDir = &m_pNtHeaders->OptionalHeader.DataDirectory[2];
                if (pResourceDir->VirtualAddress != NULL) {     //资源不为空
                    pResourcePtr = (PCHAR)RVAToPtr(pResourceDir->VirtualAddress);
                    nResourceSize = pResourceDir->Size;

                    UINT nFirstResSize;
                    PCHAR pFirstResADDR = NULL;
                    UINT FirstResADDR = NULL;
                    FirstResADDR = FindFirstResADDR();
                    nResourceDirSize = FirstResADDR - pResourceDir->VirtualAddress;     //FirstResADDR前面函数写好了，找到资源数据项地址最小的那个，做为资源数据的起点
                                                                                        //看来这个分界线之前的不能被压缩
                    WriteFile(hPackFile, (PCHAR)pResourcePtr, nResourceDirSize, &NumberOfBytes, NULL);
                    pFirstResADDR = (PCHAR)RVAToPtr(FirstResADDR);
                    nFirstResSize = nResourceSize - nResourceDirSize;   //从First开始的Res的大小

                    PackData(pFirstResADDR, nFirstResSize);
                    nRawSize = AlignSize(m_nPackSize + nResourceDirSize, nFileAlign);
                    WriteFile(hPackFile, (PCHAR)m_pPackData, m_nPackSize, &NumberOfBytes, NULL);
                    if (nRawSize - m_nPackSize - nResourceDirSize > 0) {        //压缩和未压缩的部分总和之外对齐填0
                        FillZero((PCHAR)hPackFile, nRawSize - m_nPackSize - nResourceDirSize);
                    }
                    pSecHeader->SizeOfRawData = nRawSize;
                    AddPackInfo(FirstResADDR, nFirstResSize, m_nPackSize);
                }
            }
            else {
                nRawSize = AlignSize(nNewSize, nFileAlign);
                WriteFile(hPackFile, (PCHAR)m_pPackData, nRawSize, &NumberOfBytes, NULL);
                pSecHeader->SizeOfRawData = nRawSize;
            }
        }
        if (nIndex != nSectionNum - 1) {
            (pSecHeader + 1)->PointerToRawData = pSecHeader->PointerToRawData + pSecHeader->SizeOfRawData;
        }
        pSecHeader->Characteristics |= IMAGE_SCN_MEM_WRITE;
    }
    return TRUE;
}


bool IsPEFile() {

    return true;
}


/*
//函数将特定类型的资源移动到指定位置，资源类型有03h-ICON, Gourp Icon-0Eh,10h-Version Information
//ResType   资源ID
//MoveADDR  目标地址 如果为0，函数不移动数据，只返回数据大小
//MoveResSize 上次移动的资源的大小
BOOL MovRes(UINT ResType, PCHAR MoveADDR, UINT MoveResSize) {
    
    PIMAGE_DATA_DIRECTORY   pResourceDir = NULL;
    PIMAGE_RESOURCE_DIRECTORY pResource = NULL;
    PIMAGE_RESOURCE_DIRECTORY pTypeRes = NULL;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pTypeEntry = NULL;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pNameIdEntry = NULL;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pLanguageEntry = NULL;
    PIMAGE_RESOURCE_DIRECTORY pNameIdRes = NULL;
    PIMAGE_RESOURCE_DIRECTORY pLanguageRes = NULL;
    PIMAGE_RESOURCE_DATA_ENTRY pResData = NULL;
    PCHAR pOffsetToDataPtr = NULL;

    int nTypeNum = 0;
    int nNameIdNum = 0;
    int nLanguageNum = 0;
    int nLanguageIndex = 0;

    DWORD mShell0_nSize = (DWORD)(&ShellEnd0) - (DWORD)(&ShellStart0);  //这俩变量哪里来的？汇编代码来的，壳的起止位置
    pResourceDir = &m_pNtHeaders->OptionalHeader.DataDirectory[2];
    if (pResourceDir->VirtualAddress == NULL)   //没有资源
        return FALSE;
    pResource = (PIMAGE_RESOURCE_DIRECTORY)RVAToPtr(pResourceDir->VirtualAddress);
    pTypeRes = pResource;
    nTypeNum = pTypeRes->NumberOfIdEntries + pTypeRes->NumberOfNamedEntries;
    pTypeEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pTypeRes + sizeof(PIMAGE_RESOURCE_DIRECTORY));
    for (int nTypeIndex = 0; nTypeIndex < nTypeNum; nTypeIndex++, pTypeEntry++) {
        if (pTypeEntry->NameIsString == 0) {
            if ((DWORD)pTypeEntry->NameOffset == ResType) {     //找到目标类型了
                pNameIdRes = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResource + pTypeEntry->OffsetToDirectory); //NameId这里指二级目录资源ID
                nNameIdNum = pNameIdRes->NumberOfIdEntries + pNameIdRes->NumberOfNamedEntries;
                pNameIdEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResource + sizeof(PIMAGE_RESOURCE_DIRECTORY));

                for (int nNameIdIndex = 0; nNameIdIndex < nNameIdNum; nNameIdIndex++, pNameIdEntry++) {
                    pLanguageRes = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResource + (DWORD)pNameIdEntry->OffsetToDirectory);
                    nLanguageNum = pLanguageRes->NumberOfIdEntries + pLanguageRes->NumberOfNamedEntries;
                    pLanguageEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pLanguageEntry + sizeof(PIMAGE_RESOURCE_DIRECTORY));

                    for (nLanguageIndex = 0; nLanguageIndex < nLanguageNum; nLanguageIndex++, pLanguageEntry++) {
                        pResData = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pResource + pLanguageEntry->OffsetToData);
                        if (MoveADDR) {
                            pOffsetToDataPtr = (PCHAR)RVAToPtr(pResData->OffsetToData);     //资源的（位置）偏移，不是相对于资源区开头了
                            pResData->OffsetToData = m_nImageSize + mShell0_nSize + MoveResSize;  //这里为什么？调整资源数据的位置，放到整个映像以及头的后面
                            memcpy(MoveADDR + MoveResSize, pOffsetToDataPtr, pResData->Size);
                            ZeroMemory(pOffsetToDataPtr, pResData->Size);
                        }
                        MoveResSize += pResData->Size;
                    }
                }
                return MoveResSize;     //搬完了就返回了
            }
        }
    }
    return 0;
}
*/

int main() {
    IMAGE_DOS_HEADER dosHeader = { NULL };
    IMAGE_NT_HEADERS ntHeaders = { NULL };
    DWORD NumberOfBytes;
    bool flag;


    LPCWSTR szFilePath = L"C:\\Users\\42914\\Desktop\\shell\\tls.exe";
    PPRE RBEGIN(File)
    HANDLE hFile = CreateFileW(szFilePath, GENERIC_READ | GENERIC_WRITE, \
        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING\
        ,FILE_ATTRIBUTE_NORMAL, NULL);
    //https://blog.csdn.net/li_wen01/article/details/80142931
    if (hFile == INVALID_HANDLE_VALUE) {
        WPRE printf("Wrong! Open Failed.\n");
        return (int)false;
    }
    RPRE RDONE(File);
    int nFileSize = GetFileSize(hFile, NULL);
    printf("FileSize = %d\n", nFileSize);
    NL;


    //读dos头
    PPRE RBEGIN(dosHeader)
    flag = ReadFile(hFile, &dosHeader, sizeof(dosHeader), &NumberOfBytes, NULL);
    if (flag == 0) {
        WROPRE printf("Error in reading dosHeader!\n");
        return (int)false;
    }
    RPRE RDONE(dosHeader)
    INFO(dosHeader)
    printf("DosHeader.e_magic = 0x%04X\n", htons(dosHeader.e_magic));
    printf("DosHeader.e_lfanew = 0x%08x\n", dosHeader.e_lfanew);
    NL;
    
    SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN);
    
    //读nt头
    PPRE RBEGIN(ntHeaders)
    flag = ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &NumberOfBytes, NULL);
    if (flag == 0) {
        WROPRE printf("Error in Reading ntHeaders;\n");
    }
    RIPRE RDONE(ntHeaders)
    int nSectionNum = ntHeaders.FileHeader.NumberOfSections;
    int nImageSize = ntHeaders.OptionalHeader.SizeOfImage;
    int nFileAlign = ntHeaders.OptionalHeader.FileAlignment;    //文件中的对齐值
    int nSectionAlign = ntHeaders.OptionalHeader.SectionAlignment;//内存中的对齐值
    int nHeaderSize = ntHeaders.OptionalHeader.SizeOfHeaders;   
    m_nImageSize = AlignSize(nImageSize, nSectionAlign);    //意思是文件头的nImageSize字段不一定按照对齐值的
    INFO(ntHeaders);
    printf("SectionNum   = 0x%04x = %d\n", nSectionNum, nSectionNum);
    printf("ImageSize    = 0x%08x = %d", nImageSize, nImageSize);
    REMARK(AlignedImageSize = 0x%08x = %d\n, m_nImageSize, m_nImageSize);
    printf("FileAlign    = 0x%08x = %d\n", nFileAlign, nFileAlign);
    printf("SectionAlign = 0x%08x = %d\n", nSectionAlign, nSectionAlign);
    printf("HeaderSize   = 0x%08x = %d\n", nHeaderSize, nHeaderSize);
    NL;

    PPRE printf("Initing Virtual Space...\n");
    m_pImageBase = new char[m_nImageSize];
    memset(m_pImageBase, 0, m_nImageSize);
    RIPRE printf("Virtual Space Inited\n");

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    //读整个PE头，节区头也在PE头里，所以需要重新读入整个PE头
    PPRE RBEGIN(Whole Header to Virtual Space);
    flag = ReadFile(hFile, m_pImageBase, nHeaderSize, &NumberOfBytes, NULL);
    if (flag == 0) {
        WROPRE;
        printf("Error in Reading Whole Header.\n");
        return (int)false;
    }
    RIPRE RDONE(Whole Header);
    m_pNtHeaders = (PIMAGE_NT_HEADERS)(m_pImageBase + dosHeader.e_lfanew);
    int ntHeadersSize = sizeof(ntHeaders.Signature) + sizeof(ntHeaders.FileHeader) + sizeof(ntHeaders.OptionalHeader);
    RIPRE printf("ntHeaderSize = %d\n", ntHeadersSize);
    m_pSecHeader = (PIMAGE_SECTION_HEADER)((char *)m_pNtHeaders + ntHeadersSize);
    NL;

    //读入节区
    DWORD SecSizeOfRawData = NULL;
    DWORD SecPointerToRawData = NULL;
    DWORD SecVirtualSize = NULL;
    DWORD SecVirtualAddress = NULL;
    BYTE* SecName = NULL;
    int nIndex = 0;
    char InfoSwitcher = 0;
    printf("Input y to show Sections' detail info.\n");
    InfoSwitcher = getchar();
    Addr_Trans* lnk_Addr_Trans_tmp = NULL;
    PIMAGE_SECTION_HEADER pSecHeader = m_pSecHeader;
    PPRE printf("Init Section Addr Trans Form...");
    for (; nIndex < nSectionNum; pSecHeader++, nIndex++) {           //节区头的大小是固定的，其中的name也被固定好了大小是IMAGE_SIZEOF_SHORT_NAME
        SecName = pSecHeader->Name;
        SecSizeOfRawData = pSecHeader->SizeOfRawData;
        SecPointerToRawData = pSecHeader->PointerToRawData;
        SecVirtualSize = pSecHeader->Misc.VirtualSize;
        SecVirtualAddress = pSecHeader->VirtualAddress;
        SetFilePointer(hFile, SecPointerToRawData, NULL, FILE_BEGIN);
        PPRE RBEGIN(%.8s Section to Virtual Space, SecName);
        flag = ReadFile(hFile, (m_pImageBase + SecVirtualAddress), SecSizeOfRawData, &NumberOfBytes, NULL); 
        if (flag == 0) {
            WROPRE printf("Error in reading Section %.8s", SecName);
            return (int)false;
        }
        RIPRE RDONE(Section %.8s, SecName);
        
        lnk_Addr_Trans->PointerToRawData = SecPointerToRawData;
        lnk_Addr_Trans->VirtualAddress = SecVirtualAddress;
        lnk_Addr_Trans->SizeOfRawData = SecSizeOfRawData;
        lnk_Addr_Trans->VirtualSize = SecVirtualSize;
        lnk_Addr_Trans_tmp = new Addr_Trans();
        lnk_Addr_Trans_tmp->Prev = lnk_Addr_Trans;
        lnk_Addr_Trans = lnk_Addr_Trans_tmp;

        if (InfoSwitcher == 'y') {
            INFO(% .8s Section, pSecHeader->Name);
            printf("Name:%.8s\nSizeOfRawData:0x%08x\nPointerToRawData:0x%08x\nVirtualSize:0x%08x\nVirtualAddress:0x%08x\n", \
                pSecHeader->Name, SecSizeOfRawData, SecPointerToRawData, SecVirtualSize, SecVirtualAddress);
        }
        NL;
    }
    RIPRE printf("Section Addr Trans Form Inited...\n");

    //保存额外数据，如果有额外数据的话，磁盘上文件的大小应该大于PE头指示的大小
    //书上新申请了一块空间，而不是放在之前申请的空间的后面
    //不知到这个哪里会用到
    int nExtraDataSize = nFileSize - (SecPointerToRawData + SecSizeOfRawData);
    if (nExtraDataSize > 0) {
        RIPRE printf("Extra Data Has Been Detected.\n");
        PPRE printf("Initing Extra Data Space.\n");
        char* ExtraData = new char[nExtraDataSize];
        memset(ExtraData, 0, nExtraDataSize);
        RIPRE printf("Extra Data Space Inited\n");
        PPRE RBEGIN(Extra Data to Virtual Space);
        flag = ReadFile(hFile, ExtraData, nExtraDataSize, &NumberOfBytes, NULL);
        if (flag == 0){
            WROPRE printf("Error in reading extra data.\n");
            return (int)false;
        }
        RIPRE RDONE(Extra data);
    }
    RIPRE printf("No extra data has been found.\n");
    NL;

    PCHAR temp_dump_Import = new char[m_nImageSize];    //先申请一个足够大的空间看看效果
    MoveImpTable(temp_dump_Import);

    CleanImpTable();
    
    ClsRelocData();
        
    PackFile((TCHAR *)"test.dmp");
    delete temp_dump_Import;
    
    return 0;
}