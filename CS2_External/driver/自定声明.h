#pragma once

#define POOL_TAG CLASS_TAG_LOCK_TRACKING

#define ERROR_�ɹ� 0xE0000000
#define ERROR_ʧ�� 0xE0000001

#define ERROR_�޷��򿪽��� 0xE0000002
#define ERROR_��Ч�ľ���� 0xE0000003
#define ERROR_�û���֤ʧ�� 0xE0000004
#define ERROR_�ڴ����Ͳ��� 0xE0000005
#define ERROR_�����ڴ淶Χ 0xE0000006
#define ERROR_�����ڴ�ʧ�� 0xE0000007
#define ERROR_��ѯ�ڴ�ʧ�� 0xE0000008
#define ERROR_�����ڴ�ʧ�� 0xE0000009
#define ERROR_������д�ֽ� 0xE000000A
#define ERROR_�����ڴ�ʧ�� 0xE000000B
#define ERROR_��Ч�Ļ����� 0xE000000C
#define ERROR_�޷��������� 0xE000000D
#define ERROR_�޷�ʶ������ 0xE000000E
#define ERROR_����λ������ 0xE000000F
#define ERROR_��д��ַ���� 0xE0000010
#define ERROR_�ٳ��߳�ʧ�� 0xE0000011

#define MiGetPxeAddress(BASE, VA) ((PMMPTE)BASE + ((ULONG32)(((ULONG64)(VA) >> 39) & 0x1FF)))
#define MiGetPpeAddress(BASE, VA) ((PMMPTE)(((((ULONG64)VA & 0xFFFFFFFFFFFF) >> 30) << 3) + BASE))
#define MiGetPdeAddress(BASE, VA) ((PMMPTE)(((((ULONG64)VA & 0xFFFFFFFFFFFF) >> 21) << 3) + BASE))
#define MiGetPteAddress(BASE, VA) ((PMMPTE)(((((ULONG64)VA & 0xFFFFFFFFFFFF) >> 12) << 3) + BASE))