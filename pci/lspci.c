#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <resolv.h>

#define GET16(x) do { if (p+2 > end) goto err; x = (p[0] << 8) | p[1]; p += 2; } while (0)
#define GET32(x) do { if (p+4 > end) goto err; x = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; p += 4; } while (0)

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef u8 byte;
typedef u16 word;

enum pci_lookup_mode {
  PCI_LOOKUP_VENDOR = 1,		/* Vendor name (args: vendorID) */
  PCI_LOOKUP_DEVICE = 2,		/* Device name (args: vendorID, deviceID) */
  PCI_LOOKUP_CLASS = 4,			/* Device class (args: classID) */
  PCI_LOOKUP_NETWORK = 0x80000,		/* Try to resolve unknown ID's by DNS */
};

enum id_entry_type {
  ID_VENDOR,
  ID_DEVICE,
  ID_SUBCLASS,
};

enum dns_section {
  DNS_SEC_QUESTION,
  DNS_SEC_ANSWER,
  DNS_SEC_AUTHORITY,
  DNS_SEC_ADDITIONAL,
  DNS_NUM_SECTIONS
};

struct pci_access {
    struct pci_dev *devices;
};

struct pci_dev {
  struct pci_dev *next;			/* Next device in the chain */
  int8_t bus, dev, func;			/* Bus inside domain, device and function */
  int domain;				/* PCI domain (host bridge) */
  uint16_t vendor_id, device_id;		/* Identity of the device */
  uint16_t device_class;			/* PCI device class */
};

struct dns_state {
  uint16_t counts[DNS_NUM_SECTIONS];
  byte *sections[DNS_NUM_SECTIONS+1];
  byte *sec_ptr, *sec_end;

  /* Result of dns_parse_rr(): */
  u16 rr_type;
  u16 rr_class;
  u32 rr_ttl;
  u16 rr_len;
  byte *rr_data;
};


struct pci_access *pacc;

void sysfs_scan()
{
  char dirname[1024] = "/sys/bus/pci/devices";
  DIR *dir;
  struct dirent *entry;
  dir = opendir(dirname);
  
  while ((entry = readdir(dir))) {
      struct pci_dev *d = calloc(1, sizeof(struct pci_dev));;

      if (entry->d_name[0] == '.')
	      continue;

      sscanf(entry->d_name, "%x:%hhd:%hhd.%hhd", &d->domain, &d->bus, &d->dev, &d->func);
      d->next = pacc->devices;
      pacc->devices = d;
    }
    closedir(dir);
}

void scan_devices(void)
{
  struct pci_dev *d;
  char namebuf[1024];
  int fd;
  sysfs_scan();
  for (d=pacc->devices; d; d=d->next) {
    snprintf(namebuf, 1024, "/sys/bus/pci/devices/%04x:%02x:%02x.%d/config", d->domain, d->bus, d->dev, d->func);
    fd = open(namebuf, O_RDONLY);
    pread(fd, &d->vendor_id, 2, 0); 
    pread(fd, &d->device_id, 2, 2);
    pread(fd, &d->device_class, 2, 0xa);
  }
}

byte *dns_skip_name(byte *p, byte *end)
{
  while (p < end) {
    unsigned int x = *p++;
    if (!x)
	    return p;
    switch (x & 0xc0) {
	    case 0:		/* Uncompressed: x = length */
	      p += x;
	      break;
	    case 0xc0:	/* Indirection: 1 byte more for offset */
	      p++;
	      return (p < end) ? p : NULL;
	  }
  }
  return NULL;
}

int dns_parse_packet(struct dns_state *s, uint8_t *p, unsigned int plen)
{
  uint8_t *end = p + plen;
  unsigned int i, j, len;
  unsigned int x;

  GET32(x);				/* ID and flags are ignored */
  for (i=0; i<DNS_NUM_SECTIONS; i++)
    GET16(s->counts[i]);
  for (i=0; i<DNS_NUM_SECTIONS; i++) {
      s->sections[i] = p;
      for (j=0; j < s->counts[i]; j++) {
	      p = dns_skip_name(p, end);	/* Name */
	      if (!p)
	        goto err;
	      GET32(x);			/* Type and class */
	      if (i != DNS_SEC_QUESTION) {
	        GET32(x);			/* TTL */
	        GET16(len);		/* Length of data */
	        p += len;
	        if (p > end)
		        goto err;
	      }
	  }
  }
  s->sections[i] = p;
  return 0;

err:
  return -1;
}

int dns_parse_rr(struct dns_state *s)
{
  byte *p = s->sec_ptr;
  byte *end = s->sec_end;

  if (p == end)
    return 0;
  p = dns_skip_name(p, end);
  GET16(s->rr_type);
  GET16(s->rr_class);
  GET32(s->rr_ttl);
  GET16(s->rr_len);
  s->rr_data = p;
  return 1;

err:
  return -1;
}

char *pci_id_net_lookup(int cat, int id1, int id2)
{
  static int resolver_inited;
  char name[256], dnsname[256], txt[256], domain[256] = "pci.id.ucw.cz";
  char answer[4096];
  const char *data;
  int res, j, dlen;
  struct dns_state ds;
  switch (cat) {
    case ID_VENDOR:
      sprintf(name, "%04x", id1);
      break;
    case ID_DEVICE:
      sprintf(name, "%04x.%04x", id2, id1);
      break;
    case ID_SUBCLASS:
      sprintf(name, "%02x.%02x.c", id2, id1);
      break;
  }
  sprintf(dnsname, "%.100s.%.100s", name, domain);

  if (!resolver_inited) {
      resolver_inited = 1;
      res_init();
  }
  
  res = res_query(dnsname, ns_c_in, ns_t_txt, answer, sizeof(answer));
  if (res < 0)
      return NULL;
  
  dns_parse_packet(&ds, answer, res);
  ds.sec_ptr = ds.sections[DNS_SEC_ANSWER];
  ds.sec_end = ds.sections[DNS_SEC_ANSWER+1];
  while (dns_parse_rr(&ds) > 0) {
      data = ds.rr_data;
      dlen = ds.rr_len;
      j = 0;
      while (j < dlen) {
	      memcpy(txt, &data[j+1], data[j]);
	      txt[data[j]] = 0;
	      j += 1+data[j];
	      if (txt[0] == 'i' && txt[1] == '=')
	        return strdup(txt+2);
	    }
    }

  return NULL;
}

char *id_lookup(int flags, int cat, int id1, int id2)
{
  char *name;
  int cnt = 3;
  while (!(name = pci_id_net_lookup(cat, id1, id2)) && cnt--);
  return name;
}

char *pci_lookup_name(char *buf, int size, int flags, ...)
{
  va_list args;
  char *v, *d, *cls;
  int iv, id, icls;

  va_start(args, flags);

  flags |= PCI_LOOKUP_NETWORK;
  switch (flags & 0x7fff) {
    case PCI_LOOKUP_VENDOR | PCI_LOOKUP_DEVICE:
      iv = va_arg(args, int);
      id = va_arg(args, int);
      v = id_lookup(flags, ID_VENDOR, iv, 0);
      d = id_lookup(flags, ID_DEVICE, iv, id);
      snprintf(buf, size, "%s %s", v, d);
      break;

    case PCI_LOOKUP_CLASS:
      icls = va_arg(args, int);
      cls = id_lookup(flags, ID_SUBCLASS, icls >> 8, icls & 0xff);
      snprintf(buf, size, "%s", cls);
      break;
    }
    
    va_end(args);
    return buf;
}

void show() 
{
  struct pci_dev *d;
  for (d=pacc->devices; d; d=d->next) {
    char classbuf[128], devbuf[128];
    printf("%02x:%02x.%d", d->bus, d->dev, d->func);
    printf(" %s: %s\n",
	   pci_lookup_name(classbuf, sizeof(classbuf),
		  	 PCI_LOOKUP_CLASS,
			   d->device_class),
	   pci_lookup_name(devbuf, sizeof(devbuf),
		  	 PCI_LOOKUP_VENDOR | PCI_LOOKUP_DEVICE,
			   d->vendor_id, d->device_id));
  }
}

int main() {
    pacc = calloc(1, sizeof(struct pci_access));
    scan_devices();
    show();
}