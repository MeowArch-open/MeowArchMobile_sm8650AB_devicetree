#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef AUTH_FILE_PATH
#define AUTH_FILE_PATH "/etc/zorn-charger-auth/records.bin"
#endif
#define AUTH_FILE_VERSION 1U
#define AUTH_FILE_HEADER_SIZE 40U
#define AUTH_FILE_RECORD_SIZE 52U
#define AUTH_FILE_MAX_RECORDS 10U
#define AUTH_SEED_SIZE 16U
#define AUTH_KEY_SIZE 32U
#define SHA256_BLOCK_SIZE 64U
#define SHA256_DIGEST_SIZE 32U
#define UVDM_WORDS 4U
#define UVDM_BYTES (UVDM_WORDS * 4U)
#define UVDM_HEX_LEN (UVDM_BYTES * 2U)
#define XIAOMI_SVID 0x2717U
#define POLL_ATTEMPTS 20U
#define POLL_DELAY_MS 20U
#define WRITE_ATTEMPTS 3U
#define DAEMON_RETRY_SECONDS 5U
#define AUXILIARY_DEVICES_PATH "/sys/bus/auxiliary/devices"
#define AUXILIARY_DEVICE_PREFIX "pmic_glink.power-supply."
#define DIAGNOSTICS_DIRECTORY "charger_diagnostics"
#define USB_ONLINE_PATH "/sys/class/power_supply/qcom-battmgr-usb/online"
#ifndef ZORN_CHARGER_AUTH_ENABLE_LIVE
#define ZORN_CHARGER_AUTH_ENABLE_LIVE 0
#endif

static const uint8_t auth_file_magic[8] = {'Z', 'O', 'R', 'N', 'A', 'U', 'T', 'H'};
static volatile sig_atomic_t stop_requested;

struct sha256_ctx {
	uint32_t state[8];
	uint64_t total;
	uint8_t block[SHA256_BLOCK_SIZE];
	size_t used;
};

struct auth_file {
	void *mapping;
	size_t mapping_size;
	uint32_t record_count;
};

struct auth_record {
	uint32_t index;
	uint8_t seed[AUTH_SEED_SIZE];
	uint8_t key[AUTH_KEY_SIZE];
};

enum charger_attr {
	ATTR_USB_ONLINE,
	ATTR_ADAPTER_SVID,
	ATTR_ADAPTER_ID,
	ATTR_UVDM_STATE,
	ATTR_UVDM_COMMAND,
	ATTR_VERIFY_PROCESS,
	ATTR_PD_AUTH_RESULT,
	ATTR_PD_VERIFIED,
	ATTR_COUNT,
};

struct charger_backend {
	void *context;
	int (*read)(void *context, enum charger_attr attr, char *buf, size_t size);
	int (*write)(void *context, enum charger_attr attr, const char *buf, size_t size);
	int (*random)(void *context, void *buf, size_t size);
	int (*sleep_ms)(void *context, unsigned int milliseconds);
};

struct sysfs_backend {
	char diagnostics[PATH_MAX];
};

struct state_payload {
	uint32_t state;
	char payload[UVDM_HEX_LEN + 1U];
};

struct mock_write {
	enum charger_attr attr;
	char value[48];
};

struct mock_backend {
	struct auth_record record;
	uint8_t challenge[UVDM_BYTES];
	uint32_t adapter_id;
	uint32_t svid;
	unsigned int state;
	unsigned int previous_state;
	unsigned int delay_reads;
	unsigned int delay_each;
	unsigned int sleeps;
	unsigned int writes;
	unsigned int svid_delay_reads;
	struct mock_write transcript[16];
	bool verify_started;
	bool verified_response;
	bool committed;
	bool wrong_response;
	bool disconnect_on_response;
	bool pdr_on_response;
	bool never_advance;
	unsigned int write_eagain;
};

static void secure_erase(void *data, size_t len)
{
	volatile uint8_t *p = data;

	while (len--)
		*p++ = 0;
}

static uint32_t load_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t load_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t value)
{
	p[0] = (uint8_t)(value >> 24);
	p[1] = (uint8_t)(value >> 16);
	p[2] = (uint8_t)(value >> 8);
	p[3] = (uint8_t)value;
}

static uint32_t rotr32(uint32_t value, unsigned int bits)
{
	return (value >> bits) | (value << (32U - bits));
}

static void sha256_transform(struct sha256_ctx *ctx, const uint8_t block[64])
{
	static const uint32_t k[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};
	uint32_t w[64], a, b, c, d, e, f, g, h;
	unsigned int i;

	for (i = 0; i < 16; i++)
		w[i] = load_be32(block + i * 4U);
	for (i = 16; i < 64; i++) {
		uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
			      (w[i - 15] >> 3);
		uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
			      (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
	for (i = 0; i < 64; i++) {
		uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t t1 = h + s1 + ch + k[i] + w[i];
		uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = s0 + maj;

		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
	secure_erase(w, sizeof(w));
}

static void sha256_init(struct sha256_ctx *ctx)
{
	static const uint32_t initial[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};

	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->state, initial, sizeof(initial));
}

static void sha256_update(struct sha256_ctx *ctx, const void *input, size_t len)
{
	const uint8_t *data = input;

	ctx->total += len;
	while (len) {
		size_t take = SHA256_BLOCK_SIZE - ctx->used;
		if (take > len)
			take = len;
		memcpy(ctx->block + ctx->used, data, take);
		ctx->used += take;
		data += take;
		len -= take;
		if (ctx->used == SHA256_BLOCK_SIZE) {
			sha256_transform(ctx, ctx->block);
			ctx->used = 0;
		}
	}
}

static void sha256_final(struct sha256_ctx *ctx, uint8_t digest[32])
{
	uint64_t bits = ctx->total * 8U;
	unsigned int i;

	ctx->block[ctx->used++] = 0x80;
	if (ctx->used > 56) {
		memset(ctx->block + ctx->used, 0, SHA256_BLOCK_SIZE - ctx->used);
		sha256_transform(ctx, ctx->block);
		ctx->used = 0;
	}
	memset(ctx->block + ctx->used, 0, 56 - ctx->used);
	for (i = 0; i < 8; i++)
		ctx->block[63 - i] = (uint8_t)(bits >> (i * 8U));
	sha256_transform(ctx, ctx->block);
	for (i = 0; i < 8; i++)
		store_be32(digest + i * 4U, ctx->state[i]);
	secure_erase(ctx, sizeof(*ctx));
}

static void hmac_sha256(const uint8_t *key, size_t key_len, const void *input,
			const size_t input_len, uint8_t digest[32])
{
	struct sha256_ctx ctx;
	uint8_t key_block[64] = {0}, inner[32], ipad[64], opad[64];
	unsigned int i;

	if (key_len > sizeof(key_block)) {
		sha256_init(&ctx);
		sha256_update(&ctx, key, key_len);
		sha256_final(&ctx, key_block);
	} else {
		memcpy(key_block, key, key_len);
	}
	for (i = 0; i < sizeof(key_block); i++) {
		ipad[i] = key_block[i] ^ 0x36;
		opad[i] = key_block[i] ^ 0x5c;
	}
	sha256_init(&ctx);
	sha256_update(&ctx, ipad, sizeof(ipad));
	sha256_update(&ctx, input, input_len);
	sha256_final(&ctx, inner);
	sha256_init(&ctx);
	sha256_update(&ctx, opad, sizeof(opad));
	sha256_update(&ctx, inner, sizeof(inner));
	sha256_final(&ctx, digest);
	secure_erase(key_block, sizeof(key_block));
	secure_erase(inner, sizeof(inner));
	secure_erase(ipad, sizeof(ipad));
	secure_erase(opad, sizeof(opad));
}

static bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
	uint8_t difference = 0;

	while (len--)
		difference |= *a++ ^ *b++;
	return difference == 0;
}

static int fill_random(void *buffer, size_t len)
{
	uint8_t *p = buffer;

	while (len) {
		ssize_t got = getrandom(p, len, 0);

		if (got < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!got) {
			errno = EIO;
			return -1;
		}
		p += got;
		len -= (size_t)got;
	}
	return 0;
}

static int crypto_self_test(void)
{
	static const uint8_t sha_expected[32] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	};
	static const uint8_t hmac_expected[32] = {
		0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
		0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
		0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
		0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
	};
	static const uint8_t hmac_key[20] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	};
	struct sha256_ctx ctx;
	uint8_t digest[32], random_bytes[16];
	int ret = -1;

	sha256_init(&ctx);
	sha256_update(&ctx, "abc", 3);
	sha256_final(&ctx, digest);
	if (!constant_time_equal(digest, sha_expected, sizeof(digest)))
		goto out;
	hmac_sha256(hmac_key, sizeof(hmac_key), "Hi There", 8, digest);
	if (!constant_time_equal(digest, hmac_expected, sizeof(digest)))
		goto out;
	if (fill_random(random_bytes, sizeof(random_bytes)) < 0)
		goto out;
	ret = 0;
out:
	secure_erase(digest, sizeof(digest));
	secure_erase(random_bytes, sizeof(random_bytes));
	return ret;
}

static int read_all(int fd, uint8_t *buf, size_t len)
{
	while (len) {
		ssize_t got = read(fd, buf, len);
		if (got < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!got) {
			errno = EIO;
			return -1;
		}
		buf += got;
		len -= (size_t)got;
	}
	return 0;
}

static bool mode_is_0600(mode_t mode)
{
	return (mode & 07777) == 0600;
}

static int auth_file_open(struct auth_file *file)
{
	struct stat st;
	uint8_t *data;
	uint32_t version, header_size, record_size, record_count;
	uint32_t seed_size, key_size, flags, reserved;
	size_t expected, page_size, mapping_size;
	int fd = -1, ret = -1;
	uint32_t seen = 0, i;

	memset(file, 0, sizeof(*file));
	fd = open(AUTH_FILE_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	if (fstat(fd, &st) < 0)
		goto out;
	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || !mode_is_0600(st.st_mode)) {
		errno = EPERM;
		goto out;
	}
	if (st.st_size < AUTH_FILE_HEADER_SIZE || st.st_size > 4096) {
		errno = EINVAL;
		goto out;
	}
	page_size = (size_t)sysconf(_SC_PAGESIZE);
	if (!page_size || page_size == (size_t)-1) {
		errno = EINVAL;
		goto out;
	}
	mapping_size = ((size_t)st.st_size + page_size - 1U) & ~(page_size - 1U);
	data = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (data == MAP_FAILED)
		goto out;
	file->mapping = data;
	file->mapping_size = mapping_size;
	if (mlock(data, mapping_size) < 0)
		goto out_file;
	if (madvise(data, mapping_size, MADV_DONTDUMP) < 0)
		goto out_file_locked;
	if (read_all(fd, data, (size_t)st.st_size) < 0)
		goto out_file_locked;
	if (memcmp(data, auth_file_magic, sizeof(auth_file_magic)) != 0) {
		errno = EINVAL;
		goto out_file_locked;
	}
	version = load_le32(data + 8);
	header_size = load_le32(data + 12);
	record_size = load_le32(data + 16);
	record_count = load_le32(data + 20);
	seed_size = load_le32(data + 24);
	key_size = load_le32(data + 28);
	flags = load_le32(data + 32);
	reserved = load_le32(data + 36);
	if (version != AUTH_FILE_VERSION || header_size != AUTH_FILE_HEADER_SIZE ||
	    record_size != AUTH_FILE_RECORD_SIZE || seed_size != AUTH_SEED_SIZE ||
	    key_size != AUTH_KEY_SIZE || !record_count ||
	    record_count > AUTH_FILE_MAX_RECORDS || flags || reserved) {
		errno = EINVAL;
		goto out_file_locked;
	}
	expected = header_size + (size_t)record_count * record_size;
	if (expected != (size_t)st.st_size) {
		errno = EINVAL;
		goto out_file_locked;
	}
	for (i = 0; i < record_count; i++) {
		uint32_t index = load_le32(data + header_size + (size_t)i * record_size);
		if (index >= AUTH_FILE_MAX_RECORDS || (seen & (1U << index))) {
			errno = EINVAL;
			goto out_file_locked;
		}
		seen |= 1U << index;
	}
	file->record_count = record_count;
	ret = 0;
	goto out;
out_file_locked:
	secure_erase(file->mapping, file->mapping_size);
	munlock(file->mapping, file->mapping_size);
out_file:
	munmap(file->mapping, file->mapping_size);
	memset(file, 0, sizeof(*file));
out:
	if (fd >= 0)
		close(fd);
	return ret;
}

static void auth_file_close(struct auth_file *file)
{
	if (!file->mapping)
		return;
	secure_erase(file->mapping, file->mapping_size);
	munlock(file->mapping, file->mapping_size);
	munmap(file->mapping, file->mapping_size);
	memset(file, 0, sizeof(*file));
}

static int auth_file_record_at(const struct auth_file *file, uint32_t slot,
			       struct auth_record *record)
{
	const uint8_t *data = file->mapping;
	const uint8_t *source;

	if (slot >= file->record_count) {
		errno = ERANGE;
		return -1;
	}
	source = data + AUTH_FILE_HEADER_SIZE + (size_t)slot * AUTH_FILE_RECORD_SIZE;
	record->index = load_le32(source);
	memcpy(record->seed, source + 4, sizeof(record->seed));
	memcpy(record->key, source + 4 + AUTH_SEED_SIZE, sizeof(record->key));
	return 0;
}

static int random_bounded(uint32_t upper, uint32_t *value)
{
	uint32_t random_value, limit;

	if (!upper) {
		errno = EINVAL;
		return -1;
	}
	limit = UINT32_MAX - (UINT32_MAX % upper);
	do {
		if (fill_random(&random_value, sizeof(random_value)) < 0)
			return -1;
	} while (random_value >= limit);
	*value = random_value % upper;
	return 0;
}

static int auth_file_random_record(const struct auth_file *file,
				   struct auth_record *record)
{
	uint32_t slot;

	if (random_bounded(file->record_count, &slot) < 0)
		return -1;
	return auth_file_record_at(file, slot, record);
}

static int read_fd_bounded(int fd, char *buf, size_t size)
{
	size_t used = 0;

	if (size < 2) {
		errno = EINVAL;
		return -1;
	}
	while (used < size - 1U) {
		ssize_t got = read(fd, buf + used, size - 1U - used);
		if (got < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!got)
			break;
		used += (size_t)got;
	}
	if (used == size - 1U) {
		char extra;
		ssize_t got;
		do {
			got = read(fd, &extra, 1);
		} while (got < 0 && errno == EINTR);
		if (got != 0) {
			errno = got < 0 ? errno : E2BIG;
			return -1;
		}
	}
	buf[used] = '\0';
	return 0;
}

static int write_fd_all(int fd, const char *buf, size_t size)
{
	size_t written = 0;

	while (written < size) {
		ssize_t done = write(fd, buf + written, size - written);
		if (done < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!done) {
			errno = EIO;
			return -1;
		}
		written += (size_t)done;
	}
	return 0;
}

static bool auxiliary_suffix_valid(const char *suffix)
{
	if (!*suffix)
		return false;
	while (*suffix) {
		if (*suffix < '0' || *suffix > '9')
			return false;
		suffix++;
	}
	return true;
}

static int discover_sysfs_backend(struct sysfs_backend *backend)
{
	const size_t prefix_len = strlen(AUXILIARY_DEVICE_PREFIX);
	struct dirent *entry;
	struct stat st;
	DIR *directory;
	unsigned int matches = 0;

	memset(backend, 0, sizeof(*backend));
	directory = opendir(AUXILIARY_DEVICES_PATH);
	if (!directory)
		return -1;
	while ((entry = readdir(directory)) != NULL) {
		char candidate[PATH_MAX];
		int length;

		if (strncmp(entry->d_name, AUXILIARY_DEVICE_PREFIX, prefix_len) ||
		    !auxiliary_suffix_valid(entry->d_name + prefix_len))
			continue;
		length = snprintf(candidate, sizeof(candidate), "%s/%s/%s",
				  AUXILIARY_DEVICES_PATH, entry->d_name,
				  DIAGNOSTICS_DIRECTORY);
		if (length < 0 || (size_t)length >= sizeof(candidate))
			continue;
		if (stat(candidate, &st) < 0 || !S_ISDIR(st.st_mode))
			continue;
		matches++;
		if (matches == 1)
			memcpy(backend->diagnostics, candidate, (size_t)length + 1U);
	}
	closedir(directory);
	if (matches != 1) {
		errno = matches ? EEXIST : ENOENT;
		memset(backend, 0, sizeof(*backend));
		return -1;
	}
	return 0;
}

static const char *diagnostic_attribute_name(enum charger_attr attr)
{
	switch (attr) {
	case ATTR_ADAPTER_SVID:
		return "adapter_svid";
	case ATTR_ADAPTER_ID:
		return "adapter_id";
	case ATTR_UVDM_STATE:
		return "uvdm_state";
	case ATTR_UVDM_COMMAND:
		return "uvdm_command";
	case ATTR_VERIFY_PROCESS:
		return "verify_process";
	case ATTR_PD_AUTH_RESULT:
		return "pd_auth_result";
	case ATTR_PD_VERIFIED:
		return "pd_verified";
	default:
		return NULL;
	}
}

static int sysfs_attribute_path(const struct sysfs_backend *backend,
				enum charger_attr attr, char *path, size_t size)
{
	const char *name;
	int length;

	if (attr == ATTR_USB_ONLINE) {
		if (strlen(USB_ONLINE_PATH) >= size) {
			errno = ENAMETOOLONG;
			return -1;
		}
		strcpy(path, USB_ONLINE_PATH);
		return 0;
	}
	name = diagnostic_attribute_name(attr);
	if (!name) {
		errno = EACCES;
		return -1;
	}
	length = snprintf(path, size, "%s/%s", backend->diagnostics, name);
	if (length < 0 || (size_t)length >= size) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return 0;
}

static int sysfs_read(void *context, enum charger_attr attr, char *buf, size_t size)
{
	struct sysfs_backend *backend = context;
	char path[PATH_MAX];
	int fd, ret, saved_errno;

	if (sysfs_attribute_path(backend, attr, path, sizeof(path)) < 0)
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	ret = read_fd_bounded(fd, buf, size);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return ret;
}

static int sysfs_write(void *context, enum charger_attr attr,
		       const char *buf, size_t size)
{
	struct sysfs_backend *backend = context;
	char path[PATH_MAX];
	int fd, ret, saved_errno;

	if (attr != ATTR_UVDM_COMMAND && attr != ATTR_VERIFY_PROCESS &&
	    attr != ATTR_PD_AUTH_RESULT) {
		errno = EACCES;
		return -1;
	}
	if (sysfs_attribute_path(backend, attr, path, sizeof(path)) < 0)
		return -1;
	fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	ret = write_fd_all(fd, buf, size);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return ret;
}

static int backend_random(void *context, void *buf, size_t size)
{
	(void)context;
	return fill_random(buf, size);
}

static int backend_sleep_ms(void *context, unsigned int milliseconds)
{
	struct timespec request = {
		.tv_sec = (time_t)(milliseconds / 1000U),
		.tv_nsec = (long)(milliseconds % 1000U) * 1000000L,
	};
	(void)context;

	while (nanosleep(&request, &request) < 0) {
		if (errno != EINTR)
			return -1;
		if (stop_requested) {
			errno = EINTR;
			return -1;
		}
	}
	return 0;
}

static int trim_newline(char *text)
{
	size_t length = strlen(text);

	if (length && text[length - 1U] == '\n')
		text[--length] = '\0';
	if (length && text[length - 1U] == '\r')
		text[--length] = '\0';
	if (!length || text[0] == ' ' || text[0] == '\t' ||
	    text[length - 1U] == ' ' || text[length - 1U] == '\t') {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

static int parse_u32_exact(const char *text, unsigned int base, uint32_t *value)
{
	char *end;
	unsigned long parsed;

	if (!*text || *text == '+' || *text == '-') {
		errno = EINVAL;
		return -1;
	}
	errno = 0;
	parsed = strtoul(text, &end, base);
	if (errno || *end || parsed > UINT32_MAX) {
		if (!errno)
			errno = EINVAL;
		return -1;
	}
	*value = (uint32_t)parsed;
	return 0;
}

static int parse_hex_bytes(const char *hex, uint8_t *bytes, size_t size)
{
	size_t i;

	if (strlen(hex) != size * 2U) {
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < size; i++) {
		unsigned int high, low;
		char a = hex[i * 2U], b = hex[i * 2U + 1U];

		high = a >= '0' && a <= '9' ? (unsigned int)(a - '0') :
		       a >= 'a' && a <= 'f' ? (unsigned int)(a - 'a' + 10) :
		       a >= 'A' && a <= 'F' ? (unsigned int)(a - 'A' + 10) : 16U;
		low = b >= '0' && b <= '9' ? (unsigned int)(b - '0') :
		      b >= 'a' && b <= 'f' ? (unsigned int)(b - 'a' + 10) :
		      b >= 'A' && b <= 'F' ? (unsigned int)(b - 'A' + 10) : 16U;
		if (high > 15U || low > 15U) {
			errno = EINVAL;
			return -1;
		}
		bytes[i] = (uint8_t)((high << 4) | low);
	}
	return 0;
}

static void format_hex_bytes(const uint8_t *bytes, size_t size, char *hex)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < size; i++) {
		hex[i * 2U] = digits[bytes[i] >> 4];
		hex[i * 2U + 1U] = digits[bytes[i] & 0xf];
	}
	hex[size * 2U] = '\0';
}

/* Sysfs renders each firmware little-endian word as an eight-digit number. */
static void format_uvdm_words(const uint8_t bytes[UVDM_BYTES],
			      char hex[UVDM_HEX_LEN + 1U])
{
	uint8_t ordered[UVDM_BYTES];
	size_t word, byte;

	for (word = 0; word < UVDM_WORDS; word++)
		for (byte = 0; byte < 4U; byte++)
			ordered[word * 4U + byte] = bytes[word * 4U + 3U - byte];
	format_hex_bytes(ordered, sizeof(ordered), hex);
	secure_erase(ordered, sizeof(ordered));
}

static int parse_uvdm_words(const char hex[UVDM_HEX_LEN + 1U],
			    uint8_t bytes[UVDM_BYTES])
{
	uint8_t ordered[UVDM_BYTES];
	size_t word, byte;
	int ret;

	ret = parse_hex_bytes(hex, ordered, sizeof(ordered));
	if (ret < 0)
		goto out;
	for (word = 0; word < UVDM_WORDS; word++)
		for (byte = 0; byte < 4U; byte++)
			bytes[word * 4U + byte] = ordered[word * 4U + 3U - byte];
out:
	secure_erase(ordered, sizeof(ordered));
	return ret;
}

static int parse_state_payload(char *text, struct state_payload *result)
{
	char *comma;

	if (trim_newline(text) < 0)
		return -1;
	comma = strchr(text, ',');
	if (!comma || strchr(comma + 1, ',')) {
		errno = EINVAL;
		return -1;
	}
	*comma++ = '\0';
	if (parse_u32_exact(text, 10, &result->state) < 0 || result->state > 9U)
		return -1;
	if (!*comma || strlen(comma) > UVDM_HEX_LEN) {
		errno = EINVAL;
		return -1;
	}
	strcpy(result->payload, comma);
	return 0;
}

static int backend_read_u32(struct charger_backend *backend,
			    enum charger_attr attr, unsigned int base,
			    uint32_t *value)
{
	char buffer[64];

	if (backend->read(backend->context, attr, buffer, sizeof(buffer)) < 0)
		return -1;
	if (trim_newline(buffer) < 0)
		return -1;
	return parse_u32_exact(buffer, base, value);
}

static int check_online(struct charger_backend *backend)
{
	uint32_t online;

	if (backend_read_u32(backend, ATTR_USB_ONLINE, 10, &online) < 0)
		return -1;
	if (online != 1U) {
		errno = ENOTCONN;
		return -1;
	}
	return 0;
}

static int check_connection(struct charger_backend *backend)
{
	uint32_t svid;

	if (check_online(backend) < 0)
		return -1;
	if (backend_read_u32(backend, ATTR_ADAPTER_SVID, 16, &svid) < 0)
		return -1;
	if (svid != XIAOMI_SVID) {
		errno = EACCES;
		return -1;
	}
	return 0;
}

static int wait_for_xiaomi_svid(struct charger_backend *backend)
{
	unsigned int attempt;

	for (attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
		uint32_t svid;

		if (check_online(backend) < 0)
			return -1;
		if (backend_read_u32(backend, ATTR_ADAPTER_SVID, 16, &svid) == 0 &&
		    svid == XIAOMI_SVID)
			return 0;
		if (backend->sleep_ms(backend->context, POLL_DELAY_MS) < 0)
			return -1;
	}
	errno = ETIMEDOUT;
	return -1;
}

static int backend_write_retry(struct charger_backend *backend,
			       enum charger_attr attr, const char *value)
{
	unsigned int attempt;

	for (attempt = 0; attempt < WRITE_ATTEMPTS; attempt++) {
		if (backend->write(backend->context, attr, value, strlen(value)) == 0)
			return 0;
		if (errno != EAGAIN || attempt + 1U == WRITE_ATTEMPTS)
			return -1;
		if ((attr == ATTR_VERIFY_PROCESS && !strcmp(value, "1\n") ?
		     check_online(backend) : check_connection(backend)) < 0 ||
		    backend->sleep_ms(backend->context, POLL_DELAY_MS) < 0)
			return -1;
	}
	errno = EIO;
	return -1;
}

static int write_uvdm_command(struct charger_backend *backend, unsigned int command,
			      const uint8_t *payload, size_t payload_size)
{
	char value[48], hex[UVDM_HEX_LEN + 1U];
	int length;

	if (payload) {
		if (payload_size != UVDM_BYTES) {
			errno = EINVAL;
			return -1;
		}
		format_uvdm_words(payload, hex);
		length = snprintf(value, sizeof(value), "%u %s\n", command, hex);
		secure_erase(hex, sizeof(hex));
	} else {
		length = snprintf(value, sizeof(value), "%u\n", command);
	}
	if (length < 0 || (size_t)length >= sizeof(value)) {
		secure_erase(value, sizeof(value));
		errno = EOVERFLOW;
		return -1;
	}
	if (backend_write_retry(backend, ATTR_UVDM_COMMAND, value) < 0) {
		secure_erase(value, sizeof(value));
		return -1;
	}
	secure_erase(value, sizeof(value));
	return 0;
}

static int write_uvdm_verified(struct charger_backend *backend, bool verified)
{
	return backend_write_retry(backend, ATTR_UVDM_COMMAND,
				   verified ? "6 1\n" : "6 0\n");
}

static int wait_for_state(struct charger_backend *backend, uint32_t expected)
{
	unsigned int attempt;

	for (attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
		uint32_t state;

		if (stop_requested) {
			errno = EINTR;
			return -1;
		}
		if (check_connection(backend) < 0)
			return -1;
		if (backend_read_u32(backend, ATTR_UVDM_STATE, 10, &state) == 0) {
			if (state == expected)
				return 0;
		} else if (errno != EAGAIN && errno != EIO) {
			return -1;
		}
		if (backend->sleep_ms(backend->context, POLL_DELAY_MS) < 0)
			return -1;
	}
	errno = ETIMEDOUT;
	return -1;
}

static int wait_for_scalar_response(struct charger_backend *backend,
				    uint32_t expected, uint32_t *value)
{
	unsigned int attempt;

	for (attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
		char buffer[96];
		struct state_payload response;

		if (check_connection(backend) < 0)
			return -1;
		if (backend->read(backend->context, ATTR_UVDM_COMMAND,
				  buffer, sizeof(buffer)) == 0 &&
		    parse_state_payload(buffer, &response) == 0 &&
		    response.state == expected &&
		    parse_u32_exact(response.payload, 10, value) == 0)
			return 0;
		if (backend->sleep_ms(backend->context, POLL_DELAY_MS) < 0)
			return -1;
	}
	errno = ETIMEDOUT;
	return -1;
}

static int wait_for_auth_response(struct charger_backend *backend,
				  uint8_t response[UVDM_BYTES])
{
	unsigned int attempt;

	for (attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
		char buffer[96];
		struct state_payload parsed;

		if (check_connection(backend) < 0)
			return -1;
		if (backend->read(backend->context, ATTR_UVDM_COMMAND,
				  buffer, sizeof(buffer)) == 0 &&
		    parse_state_payload(buffer, &parsed) == 0 && parsed.state == 5U &&
		    parse_uvdm_words(parsed.payload, response) == 0)
			return 0;
		secure_erase(response, UVDM_BYTES);
		if (backend->sleep_ms(backend->context, POLL_DELAY_MS) < 0)
			return -1;
	}
	errno = ETIMEDOUT;
	return -1;
}

static int authenticate_session(struct charger_backend *backend,
				const struct auth_record *record)
{
	uint8_t challenge[UVDM_BYTES], response[UVDM_BYTES];
	uint8_t hmac_input[UVDM_BYTES + 4U], digest[SHA256_DIGEST_SIZE];
	uint32_t adapter_id, ignored;
	bool started = false, committed = false;
	int ret = -1, saved_errno = EIO;

	memset(challenge, 0, sizeof(challenge));
	memset(response, 0, sizeof(response));
	memset(hmac_input, 0, sizeof(hmac_input));
	memset(digest, 0, sizeof(digest));
	if (check_online(backend) < 0)
		goto out;
	if (backend_write_retry(backend, ATTR_VERIFY_PROCESS, "1\n") < 0)
		goto out;
	started = true;
	if (wait_for_xiaomi_svid(backend) < 0)
		goto out;
	if (write_uvdm_command(backend, 1U, NULL, 0) < 0 ||
	    wait_for_scalar_response(backend, 1U, &ignored) < 0 ||
	    write_uvdm_command(backend, 2U, NULL, 0) < 0 ||
	    wait_for_scalar_response(backend, 2U, &ignored) < 0 ||
	    write_uvdm_command(backend, 3U, NULL, 0) < 0 ||
	    wait_for_scalar_response(backend, 3U, &ignored) < 0)
		goto out;
	if (write_uvdm_command(backend, 4U, record->seed, sizeof(record->seed)) < 0 ||
	    wait_for_state(backend, 4U) < 0)
		goto out;
	if (backend_read_u32(backend, ATTR_ADAPTER_ID, 16, &adapter_id) < 0)
		goto out;
	if (backend->random(backend->context, challenge, sizeof(challenge)) < 0)
		goto out;
	if (write_uvdm_command(backend, 5U, challenge, sizeof(challenge)) < 0 ||
	    wait_for_auth_response(backend, response) < 0)
		goto out;
	memcpy(hmac_input, challenge, sizeof(challenge));
	store_be32(hmac_input + sizeof(challenge), adapter_id);
	hmac_sha256(record->key, sizeof(record->key), hmac_input,
		    sizeof(hmac_input), digest);
	if (!constant_time_equal(digest, response, UVDM_BYTES)) {
		(void)write_uvdm_verified(backend, false);
		errno = EKEYREJECTED;
		goto out;
	}
	if (write_uvdm_verified(backend, true) < 0 ||
	    wait_for_state(backend, 6U) < 0 ||
	    backend_write_retry(backend, ATTR_PD_AUTH_RESULT, "1\n") < 0)
		goto out;
	committed = true;
	ret = 0;
out:
	saved_errno = errno;
	if (started && !committed)
		(void)backend_write_retry(backend, ATTR_PD_AUTH_RESULT, "0\n");
	if (started && backend_write_retry(backend, ATTR_VERIFY_PROCESS, "0\n") < 0 &&
	    ret == 0) {
		ret = -1;
		saved_errno = errno;
	}
	secure_erase(challenge, sizeof(challenge));
	secure_erase(response, sizeof(response));
	secure_erase(hmac_input, sizeof(hmac_input));
	secure_erase(digest, sizeof(digest));
	errno = saved_errno;
	return ret;
}

static int mock_record_write(struct mock_backend *mock, enum charger_attr attr,
			     const char *buf, size_t size)
{
	struct mock_write *entry;

	if (mock->writes >= sizeof(mock->transcript) / sizeof(mock->transcript[0]) ||
	    size >= sizeof(mock->transcript[0].value)) {
		errno = ENOSPC;
		return -1;
	}
	entry = &mock->transcript[mock->writes++];
	entry->attr = attr;
	memcpy(entry->value, buf, size);
	entry->value[size] = '\0';
	return 0;
}

static int mock_write(void *context, enum charger_attr attr,
		      const char *buf, size_t size)
{
	struct mock_backend *mock = context;
	char expected[48], hex[UVDM_HEX_LEN + 1U];
	unsigned int command;

	if (mock->write_eagain) {
		mock->write_eagain--;
		errno = EAGAIN;
		return -1;
	}
	if (mock_record_write(mock, attr, buf, size) < 0)
		return -1;
	if (attr == ATTR_VERIFY_PROCESS) {
		if (!strcmp(buf, "1\n")) {
			mock->verify_started = true;
			return 0;
		}
		if (!strcmp(buf, "0\n")) {
			mock->verify_started = false;
			return 0;
		}
		errno = EINVAL;
		return -1;
	}
	if (attr == ATTR_PD_AUTH_RESULT) {
		if (!strcmp(buf, "1\n")) {
			if (!mock->verified_response) {
				errno = EPERM;
				return -1;
			}
			mock->committed = true;
			return 0;
		}
		return !strcmp(buf, "0\n") ? 0 : (errno = EINVAL, -1);
	}
	if (attr != ATTR_UVDM_COMMAND || sscanf(buf, "%u", &command) != 1 ||
	    command < 1U || command > 6U) {
		errno = EINVAL;
		return -1;
	}
	if (command <= 3U)
		snprintf(expected, sizeof(expected), "%u\n", command);
	else if (command == 4U) {
		format_uvdm_words(mock->record.seed, hex);
		snprintf(expected, sizeof(expected), "4 %s\n", hex);
	} else if (command == 5U) {
		format_uvdm_words(mock->challenge, hex);
		snprintf(expected, sizeof(expected), "5 %s\n", hex);
	} else {
		if (strcmp(buf, "6 0\n") && strcmp(buf, "6 1\n")) {
			errno = EINVAL;
			return -1;
		}
		strcpy(expected, buf);
		mock->verified_response = !strcmp(buf, "6 1\n");
	}
	secure_erase(hex, sizeof(hex));
	if (strcmp(buf, expected)) {
		errno = EPROTO;
		return -1;
	}
	mock->previous_state = mock->state;
	mock->state = command;
	mock->delay_reads = mock->delay_each;
	return 0;
}

static unsigned int mock_visible_state(struct mock_backend *mock)
{
	if (mock->never_advance && mock->state == 2U)
		return mock->previous_state;
	if (mock->delay_reads) {
		mock->delay_reads--;
		return mock->previous_state;
	}
	return mock->state;
}

static int mock_read(void *context, enum charger_attr attr, char *buf, size_t size)
{
	struct mock_backend *mock = context;
	uint8_t input[UVDM_BYTES + 4U], digest[SHA256_DIGEST_SIZE];
	char hex[UVDM_HEX_LEN + 1U];
	unsigned int state;
	int length = -1;

	memset(input, 0, sizeof(input));
	memset(digest, 0, sizeof(digest));
	memset(hex, 0, sizeof(hex));
	if (mock->pdr_on_response && mock->state >= 5U) {
		errno = EIO;
		goto out;
	}
	if (attr == ATTR_USB_ONLINE) {
		bool disconnected = mock->disconnect_on_response && mock->state >= 5U;
		length = snprintf(buf, size, "%u\n", disconnected ? 0U : 1U);
	} else if (attr == ATTR_ADAPTER_SVID) {
		uint32_t visible_svid = mock->verify_started ? mock->svid : 0U;

		if (visible_svid && mock->svid_delay_reads) {
			mock->svid_delay_reads--;
			visible_svid = 0U;
		}
		length = snprintf(buf, size, "%04" PRIx32 "\n", visible_svid);
	} else if (attr == ATTR_ADAPTER_ID) {
		length = snprintf(buf, size, "%08" PRIx32 "\n", mock->adapter_id);
	} else if (attr == ATTR_PD_VERIFIED) {
		length = snprintf(buf, size, "%u\n", mock->committed ? 1U : 0U);
	} else if (attr == ATTR_UVDM_STATE) {
		length = snprintf(buf, size, "%u\n", mock_visible_state(mock));
	} else if (attr == ATTR_UVDM_COMMAND) {
		state = mock_visible_state(mock);
		if (state >= 1U && state <= 3U) {
			length = snprintf(buf, size, "%u,%u\n", state, state * 10U);
		} else if (state == 5U) {
			memcpy(input, mock->challenge, sizeof(mock->challenge));
			store_be32(input + UVDM_BYTES, mock->adapter_id);
			hmac_sha256(mock->record.key, sizeof(mock->record.key), input,
				    sizeof(input), digest);
			if (mock->wrong_response)
				digest[0] ^= 1U;
			format_uvdm_words(digest, hex);
			length = snprintf(buf, size, "5,%s\n", hex);
		} else {
			length = snprintf(buf, size, "%u,Null\n", state);
		}
	} else {
		errno = EACCES;
		goto out;
	}
	if (length < 0 || (size_t)length >= size) {
		errno = EOVERFLOW;
		length = -1;
	} else {
		length = 0;
	}
out:
	secure_erase(input, sizeof(input));
	secure_erase(digest, sizeof(digest));
	secure_erase(hex, sizeof(hex));
	return length;
}

static int mock_random(void *context, void *buf, size_t size)
{
	struct mock_backend *mock = context;

	if (size != sizeof(mock->challenge)) {
		errno = EINVAL;
		return -1;
	}
	memcpy(buf, mock->challenge, size);
	return 0;
}

static int mock_sleep(void *context, unsigned int milliseconds)
{
	struct mock_backend *mock = context;
	(void)milliseconds;
	mock->sleeps++;
	return 0;
}

static void mock_init(struct mock_backend *mock)
{
	unsigned int i;

	memset(mock, 0, sizeof(*mock));
	mock->record.index = 3;
	mock->adapter_id = 0x00007561U;
	mock->svid = XIAOMI_SVID;
	mock->svid_delay_reads = 2U;
	for (i = 0; i < AUTH_SEED_SIZE; i++) {
		mock->record.seed[i] = (uint8_t)(0xa0U + i);
		mock->challenge[i] = (uint8_t)i;
	}
	for (i = 0; i < AUTH_KEY_SIZE; i++)
		mock->record.key[i] = (uint8_t)(0x20U + i);
}

static struct charger_backend mock_operations(struct mock_backend *mock)
{
	struct charger_backend backend = {
		.context = mock,
		.read = mock_read,
		.write = mock_write,
		.random = mock_random,
		.sleep_ms = mock_sleep,
	};

	return backend;
}

static bool transcript_has(const struct mock_backend *mock,
			   enum charger_attr attr, const char *value)
{
	unsigned int i;

	for (i = 0; i < mock->writes; i++)
		if (mock->transcript[i].attr == attr &&
		    !strcmp(mock->transcript[i].value, value))
			return true;
	return false;
}

static int expect_cleanup(const struct mock_backend *mock)
{
	if (!transcript_has(mock, ATTR_PD_AUTH_RESULT, "0\n") ||
	    !transcript_has(mock, ATTR_VERIFY_PROCESS, "0\n") ||
	    transcript_has(mock, ATTR_PD_AUTH_RESULT, "1\n")) {
		errno = EPROTO;
		return -1;
	}
	return 0;
}

static int mock_self_test(void)
{
	struct mock_backend mock;
	struct charger_backend backend;
	char parse_buffer[48];
	struct state_payload parsed;
	int ret = -1;

	strcpy(parse_buffer, "5,000102030405060708090a0b0c0d0e0f\n");
	if (parse_state_payload(parse_buffer, &parsed) < 0 || parsed.state != 5U ||
	    strcmp(parsed.payload, "000102030405060708090a0b0c0d0e0f"))
		return -1;
	strcpy(parse_buffer, "5,xyz\n");
	if (parse_state_payload(parse_buffer, &parsed) < 0) {
		/* The payload parser owns the exact byte-format check. */
	} else {
		uint8_t bytes[UVDM_BYTES];
		if (parse_hex_bytes(parsed.payload, bytes, sizeof(bytes)) == 0)
			return -1;
	}

	mock_init(&mock);
	mock.delay_each = 2;
	backend = mock_operations(&mock);
	if (authenticate_session(&backend, &mock.record) < 0 || !mock.committed ||
	    mock.sleeps < 2U || mock.writes != 9U ||
	    strcmp(mock.transcript[0].value, "1\n") ||
	    strcmp(mock.transcript[1].value, "1\n") ||
	    strcmp(mock.transcript[2].value, "2\n") ||
	    strcmp(mock.transcript[3].value, "3\n") ||
	    strcmp(mock.transcript[4].value,
		   "4 a3a2a1a0a7a6a5a4abaaa9a8afaeadac\n") ||
	    strcmp(mock.transcript[5].value,
		   "5 03020100070605040b0a09080f0e0d0c\n") ||
	    strcmp(mock.transcript[6].value, "6 1\n") ||
	    mock.transcript[7].attr != ATTR_PD_AUTH_RESULT ||
	    strcmp(mock.transcript[7].value, "1\n") ||
	    mock.transcript[8].attr != ATTR_VERIFY_PROCESS ||
	    strcmp(mock.transcript[8].value, "0\n"))
		goto out;
	secure_erase(&mock, sizeof(mock));

	mock_init(&mock);
	mock.write_eagain = 2U;
	backend = mock_operations(&mock);
	if (authenticate_session(&backend, &mock.record) < 0 || !mock.committed ||
	    mock.sleeps < 2U)
		goto out;
	secure_erase(&mock, sizeof(mock));

	mock_init(&mock);
	mock.svid = 0x1234U;
	backend = mock_operations(&mock);
	if (authenticate_session(&backend, &mock.record) == 0 ||
	    !transcript_has(&mock, ATTR_VERIFY_PROCESS, "1\n") ||
	    expect_cleanup(&mock) < 0 || mock.sleeps < POLL_ATTEMPTS)
		goto out;
	secure_erase(&mock, sizeof(mock));

	mock_init(&mock);
	mock.pdr_on_response = true;
	backend = mock_operations(&mock);
	if (authenticate_session(&backend, &mock.record) == 0 ||
	    expect_cleanup(&mock) < 0)
		goto out;
	secure_erase(&mock, sizeof(mock));

	mock_init(&mock);
	mock.wrong_response = true;
	backend = mock_operations(&mock);
	if (authenticate_session(&backend, &mock.record) == 0 ||
	    expect_cleanup(&mock) < 0 ||
	    !transcript_has(&mock, ATTR_UVDM_COMMAND, "6 0\n"))
		goto out;
	secure_erase(&mock, sizeof(mock));

	mock_init(&mock);
	mock.disconnect_on_response = true;
	backend = mock_operations(&mock);
	if (authenticate_session(&backend, &mock.record) == 0 ||
	    expect_cleanup(&mock) < 0)
		goto out;
	secure_erase(&mock, sizeof(mock));

	mock_init(&mock);
	mock.never_advance = true;
	backend = mock_operations(&mock);
	if (authenticate_session(&backend, &mock.record) == 0 ||
	    expect_cleanup(&mock) < 0 || mock.sleeps < POLL_ATTEMPTS)
		goto out;
	ret = 0;
out:
	secure_erase(&mock, sizeof(mock));
	return ret;
}

static struct charger_backend sysfs_operations(struct sysfs_backend *sysfs)
{
	struct charger_backend backend = {
		.context = sysfs,
		.read = sysfs_read,
		.write = sysfs_write,
		.random = backend_random,
		.sleep_ms = backend_sleep_ms,
	};

	return backend;
}

static int authenticate_once(const struct auth_file *file)
{
	struct sysfs_backend sysfs;
	struct charger_backend backend;
	struct auth_record record;
	int ret;

	memset(&record, 0, sizeof(record));
	if (discover_sysfs_backend(&sysfs) < 0)
		return -1;
	if (auth_file_random_record(file, &record) < 0)
		return -1;
	backend = sysfs_operations(&sysfs);
	ret = authenticate_session(&backend, &record);
	secure_erase(&record, sizeof(record));
	secure_erase(&sysfs, sizeof(sysfs));
	return ret;
}

static void signal_handler(int signal_number)
{
	(void)signal_number;
	stop_requested = 1;
}

static int install_signal_handlers(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = signal_handler;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGTERM, &action, NULL) < 0 ||
	    sigaction(SIGINT, &action, NULL) < 0)
		return -1;
	return 0;
}

static int sleep_seconds(unsigned int seconds)
{
	return backend_sleep_ms(NULL, seconds * 1000U);
}

static int run_daemon(const struct auth_file *file)
{
	bool attempted_on_connection = false;

	if (install_signal_handlers() < 0)
		return -1;
	while (!stop_requested) {
		struct sysfs_backend sysfs;
		struct charger_backend backend;
		uint32_t online, svid, verified;
		bool connected = false, eligible = false;

		if (discover_sysfs_backend(&sysfs) == 0) {
			backend = sysfs_operations(&sysfs);
			if (backend_read_u32(&backend, ATTR_USB_ONLINE, 10, &online) == 0 &&
			    backend_read_u32(&backend, ATTR_ADAPTER_SVID, 16, &svid) == 0) {
				connected = online == 1U && svid == XIAOMI_SVID;
				if (connected &&
				    backend_read_u32(&backend, ATTR_PD_VERIFIED, 10, &verified) == 0)
					eligible = verified == 0U;
			}
			if (!connected)
				attempted_on_connection = false;
			if (eligible && !attempted_on_connection) {
				attempted_on_connection = true;
				if (authenticate_once(file) < 0 && !stop_requested)
					fputs("zorn-charger-auth: authentication attempt failed\n",
					      stderr);
			}
			secure_erase(&sysfs, sizeof(sysfs));
		}
		if (!stop_requested && sleep_seconds(DAEMON_RETRY_SECONDS) < 0 &&
		    errno != EINTR)
			return -1;
	}
	return 0;
}

static void usage(const char *name)
{
	fprintf(stderr,
		"usage: %s --self-test | --mock-self-test | --validate-protected | --authenticate-once | --daemon\n",
		name);
}

int main(int argc, char **argv)
{
	struct auth_file file;
	uint8_t mode_test[3] = {0};
	int ret;

	if (argc != 2) {
		usage(argv[0]);
		return 2;
	}
	if (prctl(PR_SET_DUMPABLE, 0) < 0) {
		perror("PR_SET_DUMPABLE");
		return 1;
	}
	if (crypto_self_test() < 0) {
		fputs("zorn-charger-auth: cryptographic self-test failed\n", stderr);
		return 1;
	}
	mode_test[0] = mode_is_0600(S_IFREG | 0600);
	mode_test[1] = mode_is_0600(S_IFREG | 0640);
	mode_test[2] = mode_is_0600(S_IFREG | 0700);
	if (!mode_test[0] || mode_test[1] || mode_test[2]) {
		fputs("zorn-charger-auth: protected-mode self-test failed\n", stderr);
		return 1;
	}
	if (!strcmp(argv[1], "--self-test")) {
		puts("zorn-charger-auth: self-test passed");
		return 0;
	}
	if (!strcmp(argv[1], "--mock-self-test")) {
		if (mock_self_test() < 0) {
			fputs("zorn-charger-auth: mock protocol self-test failed\n", stderr);
			return 1;
		}
		puts("zorn-charger-auth: mock protocol self-test passed");
		return 0;
	}
	if (strcmp(argv[1], "--validate-protected") &&
	    strcmp(argv[1], "--authenticate-once") && strcmp(argv[1], "--daemon")) {
		usage(argv[0]);
		return 2;
	}
	if (!ZORN_CHARGER_AUTH_ENABLE_LIVE &&
	    (!strcmp(argv[1], "--authenticate-once") || !strcmp(argv[1], "--daemon"))) {
		fputs("zorn-charger-auth: live charger transport is disabled in this build\n",
		      stderr);
		return 2;
	}
	if (auth_file_open(&file) < 0) {
		fprintf(stderr, "zorn-charger-auth: protected input rejected: %s\n",
			strerror(errno));
		return 1;
	}
	if (!strcmp(argv[1], "--validate-protected")) {
		printf("zorn-charger-auth: protected input valid (version %u, records %" PRIu32 ")\n",
		       AUTH_FILE_VERSION, file.record_count);
		ret = 0;
	} else if (!strcmp(argv[1], "--authenticate-once")) {
		ret = authenticate_once(&file);
		if (ret < 0)
			fputs("zorn-charger-auth: authentication failed\n", stderr);
		else
			puts("zorn-charger-auth: authentication completed");
	} else {
		ret = run_daemon(&file);
		if (ret < 0)
			fputs("zorn-charger-auth: daemon stopped after an error\n", stderr);
	}
	auth_file_close(&file);
	return ret < 0 ? 1 : 0;
}
