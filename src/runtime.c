/*
 *   Copyright (C) 2022, 2023 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Olaf Kirch <okir@suse.com>
 */

#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>

#include <libelf.h>
#include <libfdisk.h>
#include <linux/cdrom.h>

#include "runtime.h"
#include "bufparser.h"
#include "digest.h"
#include "testcase.h"
#include "util.h"

#define PROC_PARTITIONS_PATH	"/proc/partitions"
#define SYSFS_BLOCK_PATH	"/sys/block"

#define GPT_PREP_UUID		"9E1A2D38-C612-4316-AA26-8B49521E5A8B"
#define DOS_PREP_TYPE		0x41


struct file_locator {
	char *		partition;
	char *		relative_path;

	char *		mount_point;
	bool		is_mounted;

	char *		full_path;
};

struct block_dev_io {
	int		fd;
	unsigned int	sector_size;

	testcase_block_dev_t *recording;
};

static testcase_t *	testcase_recording;
static testcase_t *	testcase_playback;

/*
 * Testcase handling
 */
void
runtime_record_testcase(testcase_t *tc)
{
	debug("Starting testcase recording\n");
	testcase_recording = tc;
}

void
runtime_replay_testcase(testcase_t *tc)
{
	debug("Starting testcase playback\n");
	testcase_playback = tc;
}

testcase_t *
runtime_get_replay_testcase(void)
{
	return testcase_playback;
}

file_locator_t *
runtime_locate_file(const char *device_path, const char *file_path)
{
	char template[] = "/tmp/efimnt.XXXXXX";
	char fullpath[PATH_MAX];
	file_locator_t *loc;
	char *dirname;

	loc = calloc(1, sizeof(*loc));
	assign_string(&loc->partition, device_path);
	assign_string(&loc->relative_path, file_path);

	if (!(dirname = mkdtemp(template))) {
		error("Cannot create temporary mount point for EFI partition");
		return NULL;
	}

	if (mount(device_path, dirname, "vfat", 0, NULL) < 0) {
		(void) rmdir(dirname);
		error("Unable to mount %s on %s\n", device_path, dirname);
		return NULL;
	}

	assign_string(&loc->mount_point, dirname);
	loc->is_mounted = true;

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dirname, file_path);
	assign_string(&loc->full_path, fullpath);

	return loc;
}

void
file_locator_unmount(file_locator_t *loc)
{
	if (!loc->is_mounted)
		return;

	if (umount(loc->mount_point) < 0)
		fatal("unable to unmount temporary directory %s: %m\n", loc->mount_point);

	if (rmdir(loc->mount_point) < 0)
		fatal("unable to remove temporary directory %s: %m\n", loc->mount_point);

	drop_string(&loc->mount_point);
	drop_string(&loc->full_path);
	loc->is_mounted = false;
}

void
file_locator_free(file_locator_t *loc)
{
	file_locator_unmount(loc);

	drop_string(&loc->partition);
	drop_string(&loc->relative_path);
	drop_string(&loc->full_path);
}

const char *
file_locator_get_full_path(const file_locator_t *loc)
{
	return loc->full_path;
}

static buffer_t *
__system_read_efi_variable(const char *var_name)
{
	char filename[PATH_MAX];
	buffer_t *result;

	if (testcase_playback)
		return testcase_playback_efi_variable(testcase_playback, var_name);

	/* First, try new efivars interface */
	snprintf(filename, sizeof(filename), "/sys/firmware/efi/efivars/%s", var_name);
	result = buffer_read_file(filename, RUNTIME_SHORT_READ_OKAY | RUNTIME_MISSING_FILE_OKAY);
	if (result != NULL) {
		/* Skip over 4 bytes of variable attributes */
		buffer_skip(result, 4);
	} else {
		/* Fall back to old sysfs entries with their 1K limitation */
		snprintf(filename, sizeof(filename), "/sys/firmware/efi/vars/%s/data", var_name);
		result = buffer_read_file(filename, RUNTIME_SHORT_READ_OKAY | RUNTIME_MISSING_FILE_OKAY);
	}

	if (result == NULL)
		debug("Unable to read EFI variable \"%s\"\n", var_name);
	else if (testcase_recording)
		testcase_record_efi_variable(testcase_recording, var_name, result);

	return result;
}

static int
runtime_open_sysfs_file(const char *sysfs_path, const char *nickname)
{
	int fd;

	if (testcase_playback)
		return testcase_playback_sysfs_file(testcase_playback, nickname);

	fd = open(sysfs_path, O_RDONLY);
	if (fd < 0)
		return -1;

	if (testcase_recording)
		testcase_record_sysfs_file(testcase_recording, sysfs_path, nickname);
	return fd;
}

int
runtime_open_eventlog(const char *override_path)
{
	const char *eventlog_path = "/sys/kernel/security/tpm0/binary_bios_measurements";
	int fd;

	if (override_path)
		eventlog_path = override_path;

	fd = runtime_open_sysfs_file(eventlog_path, "tpm_measurements");
	if (fd < 0)
		error("Unable to open TPM event log %s: %m\n", eventlog_path);
	return fd;

}

int
runtime_open_ima_measurements(void)
{
	const char *ima_path = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements";

	return runtime_open_sysfs_file(ima_path, "ima_measurements");
}

buffer_t *
runtime_read_file(const char *path, int flags)
{
	return buffer_read_file(path, flags);
}

bool
runtime_write_file(const char *path, buffer_t *bp)
{
	return buffer_write_file(path, bp);
}

buffer_t *
runtime_read_efi_variable(const char *var_name)
{
	return __system_read_efi_variable(var_name);
}

const tpm_evdigest_t *
runtime_digest_efi_file(const tpm_algo_info_t *algo, const char *path)
{
	const tpm_evdigest_t *md;
	char esp_path[PATH_MAX];

	if (testcase_playback)
		return testcase_playback_efi_digest(testcase_playback, path, algo);

	/* FIXME: We may be better off having the caller tell us where to find the ESP.
	 * The caller should know from the previous EFI BSA event for eg grub.efi
	 * which partition is the ESP that was used. */
	snprintf(esp_path, sizeof(esp_path), "/boot/efi%s", path);
	md = digest_from_file(algo, esp_path, 0);
	if (md && testcase_recording)
		testcase_record_efi_digest(testcase_recording, path, md);

	return md;
}

const tpm_evdigest_t *
runtime_digest_rootfs_file(const tpm_algo_info_t *algo, const char *path)
{
	const tpm_evdigest_t *md;

	if (testcase_playback)
		return testcase_playback_rootfs_digest(testcase_playback, path, algo);

	md = digest_from_file(algo, path, 0);
	if (md && testcase_recording)
		testcase_record_rootfs_digest(testcase_recording, path, md);

	return md;
}

buffer_t *
runtime_read_efi_application(const char *partition, const char *application)
{
        file_locator_t *loc;
	const char *fullpath;
	buffer_t *result;

	if (testcase_playback)
		return testcase_playback_efi_application(testcase_playback, partition, application);

	debug("%s(%s, %s)\n", __func__, partition, application);
        loc = runtime_locate_file(partition, application);
        if (!loc)
                return NULL;

	if ((fullpath = file_locator_get_full_path(loc)) != NULL)
                result = runtime_read_file(fullpath, 0);

	file_locator_free(loc);

	if (result && testcase_recording)
		testcase_record_efi_application(testcase_recording, partition, application, result);

	return result;
}

static bool
is_parent_block(char *blkname)
{
	char buf[PATH_MAX];
	struct stat f_stat;

	/* Check /sys/block/<blkname>/dev */
	snprintf(buf, PATH_MAX, "%s/%s/dev", SYSFS_BLOCK_PATH, blkname);

	return (stat(buf, &f_stat) == 0);
}

#ifdef CDROM_GET_CAPABILITY
static bool
blkdev_is_cdrom(int fd)
{
	int ret;

	if ((ret = ioctl(fd, CDROM_GET_CAPABILITY, NULL)) < 0)
		return false;

	return !!ret;
}
#else
static bool
blkdev_is_cdrom(int fd __attribute__((__unused__)))
{
	return false;
}
#endif

static bool
is_cdrom_or_tape(char *device)
{
	int fd;
	bool ret;

	if ((fd = open(device, O_RDONLY|O_NONBLOCK)) < 0)
		return 0;
	ret = blkdev_is_cdrom(fd);

	close(fd);
	return ret;
}

static char *
next_proc_partition (FILE **f)
{
	char line[128 + 1];
	char buf[PATH_MAX];
	char devpath[PATH_MAX];

	if (!*f) {
		*f = fopen(PROC_PARTITIONS_PATH, "r");
		if (!*f) {
			fprintf(stderr, "cannot open %s", PROC_PARTITIONS_PATH);
			return NULL;
		}
	}

	/*
	 * Example of /proc/partitions
	 *
	 * major minor  #blocks  name
	 *
	 *    8        0   41943040 sda
	 *    8        1       8192 sda1
	 *    8        2   41933807 sda2
	 *  254        0   41917423 dm-0
	 */
	while (fgets(line, sizeof(line), *f)) {
		if (sscanf(line, " %*d %*d %*d %128[^\n ]", buf) != 1)
			continue;

		/* The partition table is only available to the parent block device */
		if (!is_parent_block(buf))
			continue;

		if (snprintf(devpath, PATH_MAX, "/dev/%s", buf) < 0)
			return NULL;

		if (!is_cdrom_or_tape(devpath))
			return strdup(devpath);
	}
	fclose(*f);
	*f = NULL;

	return NULL;
}

static int
is_prep_partition(struct fdisk_parttype *ptype, int is_gpt)
{
	const char *typestr;

	if (is_gpt) {
		typestr = fdisk_parttype_get_string(ptype);
		return !!(strcmp(typestr, GPT_PREP_UUID) == 0);
	} else {
		return !!(fdisk_parttype_get_code(ptype) == DOS_PREP_TYPE);
	}
	return 0;
}

static char *
locate_prep_partition_real(char *devname)
{
	struct fdisk_context *cxt = NULL;
	struct fdisk_table *tb = NULL;
	struct fdisk_iter *itr = NULL;
	struct fdisk_partition *part = NULL;
	struct fdisk_parttype *ptype = NULL;
	int is_gpt = 0;
	char *prep_dev = NULL;

	cxt = fdisk_new_context();

	if (fdisk_assign_device(cxt, devname, 1) < 0)
		goto done;

	/* PReP partition only in GPT or MBR */
	if (fdisk_is_labeltype(cxt, FDISK_DISKLABEL_GPT) == 1)
		is_gpt = 1;
	else if (fdisk_is_labeltype(cxt, FDISK_DISKLABEL_DOS) == 1)
		is_gpt = 0;
	else
		goto done;

	if (fdisk_get_partitions(cxt, &tb) || fdisk_table_get_nents(tb) <= 0)
		goto done;

	itr = fdisk_new_iter(FDISK_ITER_FORWARD);
	if (itr == NULL) {
		error("failed to allocate fdisk iterator\n");
		goto done;
	}

	/* Go through the partitions to find PReP partition */
	while (fdisk_table_next_partition(tb, itr, &part) == 0) {
		ptype = fdisk_partition_get_type(part);
		if (ptype == NULL)
			continue;

		if (!is_prep_partition(ptype, is_gpt))
			continue;

		fdisk_partition_to_string(part, cxt,
					  FDISK_FIELD_DEVICE,
					  &prep_dev);
		break;
	}
done:
	if (itr)
		fdisk_free_iter(itr);
	if (tb)
		fdisk_unref_table(tb);
	fdisk_unref_context(cxt);

	return prep_dev;
}

char *
runtime_locate_prep_partition(void)
{
	static char prep_dev[PATH_MAX];
	FILE *f = NULL;
	char *devname = NULL;
	char *prep_tmp = NULL;

	if (prep_dev[0] != '\0')
		return strdup(prep_dev);

	while ((devname = next_proc_partition(&f))) {
		prep_tmp = locate_prep_partition_real(devname);
		free(devname);

		if (prep_tmp != NULL) {
			snprintf(prep_dev, PATH_MAX, "%s", prep_tmp);
			break;
		}
	}

	return prep_tmp;
}

static int
calculate_elf32_size(Elf *elf, size_t max_size, size_t *result)
{
	Elf32_Ehdr *ehdr = NULL;
	Elf32_Phdr *phdrs = NULL, *phdr = NULL;
	Elf_Scn *scn = NULL;
	Elf32_Shdr *shdr = NULL;
	size_t elf_size = 0;
	int i;

	if (result == NULL)
		return -1;

	if ((ehdr = elf32_getehdr(elf)) == NULL)
		return -1;

	elf_size = ehdr->e_phoff;
	phdrs = elf32_getphdr(elf);
	if (phdrs == NULL)
		return -1;

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = phdrs + i;

		elf_size = MAX(phdr->p_offset + phdr->p_filesz, elf_size);
		if (elf_size > max_size)
			return -1;
	}

	for (i = 0; i < ehdr->e_shnum; i++) {
		if ((scn = elf_getscn(elf, i)) == NULL)
			return -1;
		if ((shdr = elf32_getshdr(scn)) == NULL)
			return -1;

		elf_size = MAX(shdr->sh_offset + shdr->sh_size, elf_size);
		if (elf_size > max_size)
			return -1;
	}

	*result = elf_size;

	return 0;
}

static int
calculate_elf64_size(Elf *elf, size_t max_size, size_t *result)
{
	Elf64_Ehdr *ehdr = NULL;
	Elf64_Phdr *phdrs = NULL, *phdr = NULL;
	Elf_Scn *scn = NULL;
	Elf64_Shdr *shdr = NULL;
	size_t elf_size = 0;
	int i;

	if (result == NULL)
		return -1;

	if ((ehdr = elf64_getehdr(elf)) == NULL)
		return -1;

	elf_size = ehdr->e_phoff;
	phdrs = elf64_getphdr(elf);
	if (phdrs == NULL)
		return -1;

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = phdrs + i;

		elf_size = MAX(phdr->p_offset + phdr->p_filesz, elf_size);
		if (elf_size > max_size)
			return -1;
	}

	for (i = 0; i < ehdr->e_shnum; i++) {
		if ((scn = elf_getscn(elf, i)) == NULL)
			return -1;
		if ((shdr = elf64_getshdr(scn)) == NULL)
			return -1;

		elf_size = MAX(shdr->sh_offset + shdr->sh_size, elf_size);
		if (elf_size > max_size)
			return -1;
	}

	*result = elf_size;

	return 0;
}

static int
prep_bootloader_size (block_dev_io_t *prep_io, size_t *result)
{
	buffer_t *buffer = NULL;
	Elf *elf = NULL;
	size_t part_size = 0;
	size_t elf_size;
	int ret = -1;

	if (result == NULL)
		return -1;

	part_size = lseek(prep_io->fd, 0, SEEK_END);

	/* The first two blocks (1KB) should be enough to cover all the ELF
	 * headers (ELF headers, program headers, and section headers). */
	if ((buffer = runtime_blockdev_read_lba(prep_io, 0, 2)) == NULL) {
		error("Unable to read the first two blocks\n");
		goto failed;
	}

	/* Read the ELF structure  */
	if ((elf = elf_memory((char *)buffer->data, buffer->size)) == NULL) {
		error("Failed to initialize Elf\n");
		goto failed;
	}

	if (elf32_getehdr(elf) != NULL) {
		ret = calculate_elf32_size(elf, part_size, &elf_size);
	} else if (elf64_getehdr(elf) != NULL) {
		ret = calculate_elf64_size(elf, part_size, &elf_size);
	} else {
		error("invalid ELF header\n");
		goto failed;
	}

	if (ret < 0) {
		error("Failed get ELF size\n");
		goto failed;
	}

	/* Follow SLOF to round up the size */
	elf_size = roundup(elf_size, 4);

	*result = elf_size;

	ret = 0;
failed:
	if (buffer)
		buffer_free(buffer);
	if (elf)
		elf_end(elf);

	return ret;
}

const tpm_evdigest_t *
runtime_digest_prep_booloader(const tpm_algo_info_t *algo, const char *prep_partition)
{
	buffer_t *buffer = NULL;
	block_dev_io_t *prep_io;
	size_t bootloader_size = 0;
	unsigned int nsector;
	const tpm_evdigest_t *md = NULL;

	if ((prep_io = runtime_blockdev_open(prep_partition)) == NULL) {
		error("Unable to open disk device %s: %m\n", prep_partition);
		goto failed;
	}

	if (prep_bootloader_size(prep_io, &bootloader_size) < 0) {
		error("%s: unable to get bootloader size\n", prep_partition);
		goto failed;
	}

	nsector = runtime_blockdev_bytes_to_sectors(prep_io, bootloader_size);

	if ((buffer = runtime_blockdev_read_lba(prep_io, 0, nsector)) == NULL) {
		error("%s: unable to read the full bootloader\n", prep_partition);
		goto failed;
	}

	md = digest_compute(algo, buffer->data, bootloader_size);

failed:
	if (prep_io >= 0)
		runtime_blockdev_close(prep_io);
	if (buffer)
		buffer_free(buffer);

	return md;
}

char *
runtime_disk_for_partition(const char *part_dev)
{
	char *part_name;
	char sys_block[PATH_MAX];
	char sys_device[PATH_MAX];
	ssize_t link_size;
	char *disk_name;
	size_t r_size;
	char *result;

	if (testcase_playback)
		return testcase_playback_partition_disk(testcase_playback, part_dev);

	/* Get the disk name from the sysfs path */
	/* example:
	 *   To get the disk device name of /dev/nvme0n1p1
	 *
	 *   Look into the link to the sysfs block device:
	 *   $ ls -l /sys/class/block/nvme0n1p1
	 *   lrwxrwxrwx 1 root root 0 Oct 19 09:53 /sys/class/block/nvme0n1p1 -> ../../devices/pci0000:00/0000:00:06.0/0000:02:00.0/nvme/nvme0/nvme0n1/nvme0n1p1
	 *
	 *   Trace back the upper level directory to get "nvme0n1"
	 *   and return "/dev/nvme0n1"
	 */
	part_name = strrchr(part_dev, '/')+1;

	snprintf(sys_block, PATH_MAX, "/sys/class/block/%s", part_name);

	link_size = readlink(sys_block, sys_device, PATH_MAX);
	if (link_size < 0) {
		error("Error when reading the link of %s: %m\n", sys_block);
		return NULL;
	} else if (link_size >= PATH_MAX) {
		error("Error insufficient buffer size for the link of %s\n", sys_block);
		return NULL;
	}
	sys_device[link_size] = '\0';
	*strrchr(sys_device, '/') = '\0';
	disk_name = strrchr(sys_device, '/')+1;

	if (testcase_recording)
		testcase_record_partition_disk(testcase_recording, part_name, disk_name);

	r_size = strlen("/dev/") + strlen(disk_name) + 1;
	result = malloc(r_size);
	if (result == NULL) {
		error("Error when allocating buffer: %m\n");
		return NULL;
	}
	snprintf(result, r_size, "/dev/%s", disk_name);

	return result;
}

char *
runtime_blockdev_by_partuuid(const char *uuid)
{
	char pathbuf[PATH_MAX];
	char *dev_name;

	if (testcase_playback)
		return testcase_playback_partition_uuid(testcase_playback, uuid);

	snprintf(pathbuf, sizeof(pathbuf), "/dev/disk/by-partuuid/%s", uuid);
	dev_name = realpath(pathbuf, NULL);

	if (dev_name && testcase_recording)
		testcase_record_partition_uuid(testcase_recording, uuid, dev_name);
	return dev_name;
}

block_dev_io_t *
runtime_blockdev_open(const char *dev)
{
	block_dev_io_t *io;
	int fd;

	if (testcase_playback)
		fd = testcase_playback_block_dev(testcase_playback, dev);
	else
	if ((fd = open(dev, O_RDONLY)) < 0)
		return NULL;

	io = calloc(1, sizeof(*io));
	io->fd = fd;
	io->sector_size = 512;

	if (testcase_recording)
		io->recording = testcase_record_block_dev(testcase_recording, dev);

	return io;
}

void
runtime_blockdev_close(block_dev_io_t *io)
{
	close(io->fd);
	io->fd = -1;

	if (io->recording) {
		testcase_block_dev_close(io->recording);
		io->recording = NULL;
	}

	free(io);
}

size_t
runtime_blockdev_bytes_to_sectors(const block_dev_io_t *io, size_t size)
{
	return (size + io->sector_size - 1) / io->sector_size;
}

buffer_t *
runtime_blockdev_read_lba(block_dev_io_t *io, size_t block, size_t count)
{
	unsigned long offset = block * io->sector_size;
	unsigned int bytes;
	buffer_t *result;
	int n;

	if (lseek(io->fd, offset, SEEK_SET) < 0) {
		error("block dev seek: %m\n");
		return NULL;
	}

	bytes = io->sector_size * count;

	result = buffer_alloc_write(bytes);
	n = read(io->fd, buffer_write_pointer(result), bytes);
	if (n < 0) {
		error("block dev read: %m\n");
		goto failed;
	}
	if (n < bytes) {
		error("block dev read: %m\n");
		goto failed;
	}
	result->wpos += bytes;

	if (io->recording)
		testcase_block_dev_write(io->recording, offset, result);

	return result;

failed:
	buffer_free(result);
	return NULL;
}

FILE *
runtime_maybe_record_pcrs(void)
{
	if (testcase_recording)
		return testcase_record_pcrs(testcase_recording, "current-pcrs");
	return NULL;
}

FILE *
runtime_maybe_playback_pcrs(void)
{
	if (testcase_playback)
		return testcase_playback_pcrs(testcase_playback, "current-pcrs");
	return NULL;
}
