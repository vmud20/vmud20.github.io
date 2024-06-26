










































MODULE_DESCRIPTION("V4L2 loopback video device");
MODULE_AUTHOR("Vasily Levin, " "IOhannes m zmoelnig <zmoelnig@iem.at>," "Stefan Diewald," "Anton Novikov" "et al.");



MODULE_VERSION("0.12.5");
MODULE_LICENSE("GPL");































struct v4l2_ctrl_handler {
	int error;
};
struct v4l2_ctrl_config {
	void *ops;
	u32 id;
	const char *name;
	int type;
	s32 min;
	s32 max;
	u32 step;
	s32 def;
};
int v4l2_ctrl_handler_init(struct v4l2_ctrl_handler *hdl, unsigned nr_of_controls_hint)
{
	hdl->error = 0;
	return 0;
}
void v4l2_ctrl_handler_free(struct v4l2_ctrl_handler *hdl)
{
}
void *v4l2_ctrl_new_custom(struct v4l2_ctrl_handler *hdl, const struct v4l2_ctrl_config *conf, void *priv)
{
	return NULL;
}





struct v4l2_device {
	char name[V4L2_DEVICE_NAME_SIZE];
	struct v4l2_ctrl_handler *ctrl_handler;
};
static inline int v4l2_device_register(void *dev, void *v4l2_dev)
{
	return 0;
}
static inline void v4l2_device_unregister(struct v4l2_device *v4l2_dev)
{
	return;
}






void *v4l2l_vzalloc(unsigned long size)
{
	void *data = vmalloc(size);

	memset(data, 0, size);
	return data;
}




static inline void v4l2l_get_timestamp(struct v4l2_buffer *b)
{
	

	struct timespec ts;
	ktime_get_ts(&ts);

	struct timespec64 ts;
	ktime_get_ts64(&ts);


	b->timestamp.tv_sec = ts.tv_sec;
	b->timestamp.tv_usec = (ts.tv_nsec / NSEC_PER_USEC);
}


typedef unsigned __poll_t;

























static int debug = 0;
module_param(debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "debugging level (higher values == more verbose)");


static int max_buffers = V4L2LOOPBACK_DEFAULT_MAX_BUFFERS;
module_param(max_buffers, int, S_IRUGO);
MODULE_PARM_DESC(max_buffers, "how many buffers should be allocated [DEFAULT: " STRINGIFY2( V4L2LOOPBACK_DEFAULT_MAX_BUFFERS) "]");




static int max_openers = V4L2LOOPBACK_DEFAULT_MAX_OPENERS;
module_param(max_openers, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC( max_openers, "how many users can open the loopback device [DEFAULT: " STRINGIFY2( V4L2LOOPBACK_DEFAULT_MAX_OPENERS) "]");



static int devices = -1;
module_param(devices, int, 0);
MODULE_PARM_DESC(devices, "how many devices should be created");

static int video_nr[MAX_DEVICES] = { [0 ...(MAX_DEVICES - 1)] = -1 };
module_param_array(video_nr, int, NULL, 0444);
MODULE_PARM_DESC(video_nr, "video device numbers (-1=auto, 0=/dev/video0, etc.)");

static char *card_label[MAX_DEVICES];
module_param_array(card_label, charp, NULL, 0000);
MODULE_PARM_DESC(card_label, "card labels for each device");

static bool exclusive_caps[MAX_DEVICES] = {
	[0 ...(MAX_DEVICES - 1)] = V4L2LOOPBACK_DEFAULT_EXCLUSIVECAPS };
module_param_array(exclusive_caps, bool, NULL, 0444);

MODULE_PARM_DESC( exclusive_caps, "whether to announce OUTPUT/CAPTURE capabilities exclusively or not  [DEFAULT: " STRINGIFY2( V4L2LOOPBACK_DEFAULT_EXCLUSIVECAPS) "]");












static int max_width = V4L2LOOPBACK_SIZE_DEFAULT_MAX_WIDTH;
module_param(max_width, int, S_IRUGO);
MODULE_PARM_DESC(max_width, "maximum allowed frame width [DEFAULT: " STRINGIFY2( V4L2LOOPBACK_SIZE_DEFAULT_MAX_WIDTH) "]");
static int max_height = V4L2LOOPBACK_SIZE_DEFAULT_MAX_HEIGHT;
module_param(max_height, int, S_IRUGO);
MODULE_PARM_DESC(max_height, "maximum allowed frame height [DEFAULT: " STRINGIFY2( V4L2LOOPBACK_SIZE_DEFAULT_MAX_HEIGHT) "]");


static DEFINE_IDR(v4l2loopback_index_idr);
static DEFINE_MUTEX(v4l2loopback_ctl_mutex);












static int v4l2loopback_s_ctrl(struct v4l2_ctrl *ctrl);
static const struct v4l2_ctrl_ops v4l2loopback_ctrl_ops = {
	.s_ctrl = v4l2loopback_s_ctrl, };
static const struct v4l2_ctrl_config v4l2loopback_ctrl_keepformat = {
	
	.ops	= &v4l2loopback_ctrl_ops, .id	= CID_KEEP_FORMAT, .name	= "keep_format", .type	= V4L2_CTRL_TYPE_BOOLEAN, .min	= 0, .max	= 1, .step	= 1, .def	= 0,  };








static const struct v4l2_ctrl_config v4l2loopback_ctrl_sustainframerate = {
	
	.ops	= &v4l2loopback_ctrl_ops, .id	= CID_SUSTAIN_FRAMERATE, .name	= "sustain_framerate", .type	= V4L2_CTRL_TYPE_BOOLEAN, .min	= 0, .max	= 1, .step	= 1, .def	= 0,  };








static const struct v4l2_ctrl_config v4l2loopback_ctrl_timeout = {
	
	.ops	= &v4l2loopback_ctrl_ops, .id	= CID_TIMEOUT, .name	= "timeout", .type	= V4L2_CTRL_TYPE_INTEGER, .min	= 0, .max	= MAX_TIMEOUT, .step	= 1, .def	= 0,  };








static const struct v4l2_ctrl_config v4l2loopback_ctrl_timeoutimageio = {
	
	.ops	= &v4l2loopback_ctrl_ops, .id	= CID_TIMEOUT_IMAGE_IO, .name	= "timeout_image_io", .type	= V4L2_CTRL_TYPE_BOOLEAN, .min	= 0, .max	= 1, .step	= 1, .def	= 0,  };










struct v4l2loopback_private {
	int device_nr;
};




struct v4l2l_buffer {
	struct v4l2_buffer buffer;
	struct list_head list_head;
	int use_count;
};

struct v4l2_loopback_device {
	struct v4l2_device v4l2_dev;
	struct v4l2_ctrl_handler ctrl_handler;
	struct video_device *vdev;
	
	struct v4l2_pix_format pix_format;
	struct v4l2_captureparm capture_param;
	unsigned long frame_jiffies;

	
	int keep_format; 
	int sustain_framerate; 

	
	u8 *image; 
	unsigned long int imagesize; 
	int buffers_number; 
	struct v4l2l_buffer buffers[MAX_BUFFERS]; 
	int used_buffers; 
	int max_openers; 

	int write_position; 
	struct list_head outbufs_list; 
	int bufpos2index [MAX_BUFFERS];
	long buffer_size;

	
	struct timer_list sustain_timer;
	unsigned int reread_count;

	
	unsigned long timeout_jiffies; 
	int timeout_image_io; 
	u8 *timeout_image; 
	struct v4l2l_buffer timeout_image_buffer;
	struct timer_list timeout_timer;
	int timeout_happened;

	
	atomic_t open_count;

	int ready_for_capture; 
	int ready_for_output; 
	int announce_all_caps; 

	int max_width;
	int max_height;

	char card_label[32];

	wait_queue_head_t read_event;
	spinlock_t lock;
};


enum opener_type {
	
	UNNEGOTIATED	= 0, READER		= 1, WRITER		= 2,  };





struct v4l2_loopback_opener {
	enum opener_type type;
	int vidioc_enum_frameintervals_calls;
	int read_position; 
	unsigned int reread_count;
	struct v4l2_buffer *buffers;
	int buffers_number; 
	int timeout_image_io;

	struct v4l2_fh fh;
};




struct v4l2l_format {
	char *name;
	int fourcc; 
	int depth; 
	int flags;
};






static const unsigned int FORMATS = ARRAY_SIZE(formats);

static char *fourcc2str(unsigned int fourcc, char buf[4])
{
	buf[0] = (fourcc >> 0) & 0xFF;
	buf[1] = (fourcc >> 8) & 0xFF;
	buf[2] = (fourcc >> 16) & 0xFF;
	buf[3] = (fourcc >> 24) & 0xFF;

	return buf;
}

static const struct v4l2l_format *format_by_fourcc(int fourcc)
{
	unsigned int i;

	for (i = 0; i < FORMATS; i++) {
		if (formats[i].fourcc == fourcc)
			return formats + i;
	}

	dprintk("unsupported format '%c%c%c%c'\n", (fourcc >> 0) & 0xFF, (fourcc >> 8) & 0xFF, (fourcc >> 16) & 0xFF, (fourcc >> 24) & 0xFF);

	return NULL;
}

static void pix_format_set_size(struct v4l2_pix_format *f, const struct v4l2l_format *fmt, unsigned int width, unsigned int height)

{
	f->width = width;
	f->height = height;

	if (fmt->flags & FORMAT_FLAGS_PLANAR) {
		f->bytesperline = width; 
		f->sizeimage = (width * height * fmt->depth) >> 3;
	} else if (fmt->flags & FORMAT_FLAGS_COMPRESSED) {
		
		f->bytesperline = 0;
		f->sizeimage = (width * height * fmt->depth) >> 3;
	} else {
		f->bytesperline = (width * fmt->depth) >> 3;
		f->sizeimage = height * f->bytesperline;
	}
}

static int set_timeperframe(struct v4l2_loopback_device *dev, struct v4l2_fract *tpf)
{
	if ((tpf->denominator < 1) || (tpf->numerator < 1)) {
		return -EINVAL;
	}
	dev->capture_param.timeperframe = *tpf;
	dev->frame_jiffies = max(1UL, msecs_to_jiffies(1000) * tpf->numerator / tpf->denominator);
	return 0;
}

static struct v4l2_loopback_device *v4l2loopback_cd2dev(struct device *cd);




static ssize_t attr_show_format(struct device *cd, struct device_attribute *attr, char *buf)
{
	
	struct v4l2_loopback_device *dev = v4l2loopback_cd2dev(cd);
	const struct v4l2_fract *tpf;
	char buf4cc[5], buf_fps[32];

	if (!dev || !dev->ready_for_capture)
		return 0;
	tpf = &dev->capture_param.timeperframe;

	fourcc2str(dev->pix_format.pixelformat, buf4cc);
	buf4cc[4] = 0;
	if (tpf->numerator == 1)
		snprintf(buf_fps, sizeof(buf_fps), "%d", tpf->denominator);
	else snprintf(buf_fps, sizeof(buf_fps), "%d/%d", tpf->denominator, tpf->numerator);

	return sprintf(buf, "%4s:%dx%d@%s\n", buf4cc, dev->pix_format.width, dev->pix_format.height, buf_fps);
}

static ssize_t attr_store_format(struct device *cd, struct device_attribute *attr, const char *buf, size_t len)

{
	struct v4l2_loopback_device *dev = v4l2loopback_cd2dev(cd);
	int fps_num = 0, fps_den = 1;

	if (!dev)
		return -ENODEV;

	
	if (sscanf(buf, "@%d/%d", &fps_num, &fps_den) > 0) {
		struct v4l2_fract f = { .numerator = fps_den, .denominator = fps_num };
		int err = 0;
		if ((err = set_timeperframe(dev, &f)) < 0)
			return err;
		return len;
	}
	return -EINVAL;
}

static DEVICE_ATTR(format, S_IRUGO | S_IWUSR, attr_show_format, attr_store_format);

static ssize_t attr_show_buffers(struct device *cd, struct device_attribute *attr, char *buf)
{
	struct v4l2_loopback_device *dev = v4l2loopback_cd2dev(cd);

	if (!dev)
		return -ENODEV;

	return sprintf(buf, "%d\n", dev->used_buffers);
}

static DEVICE_ATTR(buffers, S_IRUGO, attr_show_buffers, NULL);

static ssize_t attr_show_maxopeners(struct device *cd, struct device_attribute *attr, char *buf)
{
	struct v4l2_loopback_device *dev = v4l2loopback_cd2dev(cd);

	return sprintf(buf, "%d\n", dev->max_openers);
}

static ssize_t attr_store_maxopeners(struct device *cd, struct device_attribute *attr, const char *buf, size_t len)

{
	struct v4l2_loopback_device *dev = NULL;
	unsigned long curr = 0;

	if (kstrtoul(buf, 0, &curr))
		return -EINVAL;

	dev = v4l2loopback_cd2dev(cd);

	if (dev->max_openers == curr)
		return len;

	if (curr > __INT_MAX__ || dev->open_count.counter > curr) {
		
		return -EINVAL;
	}

	dev->max_openers = (int)curr;

	return len;
}

static DEVICE_ATTR(max_openers, S_IRUGO | S_IWUSR, attr_show_maxopeners, attr_store_maxopeners);

static void v4l2loopback_remove_sysfs(struct video_device *vdev)
{


	if (vdev) {
		V4L2_SYSFS_DESTROY(format);
		V4L2_SYSFS_DESTROY(buffers);
		V4L2_SYSFS_DESTROY(max_openers);
		
	}
}

static void v4l2loopback_create_sysfs(struct video_device *vdev)
{
	int res = 0;




	if (!vdev)
		return;
	do {
		V4L2_SYSFS_CREATE(format);
		V4L2_SYSFS_CREATE(buffers);
		V4L2_SYSFS_CREATE(max_openers);
		
	} while (0);

	if (res >= 0)
		return;
	dev_err(&vdev->dev, "%s error: %d\n", __func__, res);
}



struct v4l2loopback_lookup_cb_data {
	int device_nr;
	struct v4l2_loopback_device *device;
};
static int v4l2loopback_lookup_cb(int id, void *ptr, void *data)
{
	struct v4l2_loopback_device *device = ptr;
	struct v4l2loopback_lookup_cb_data *cbdata = data;
	if (cbdata && device && device->vdev) {
		if (device->vdev->num == cbdata->device_nr) {
			cbdata->device = device;
			cbdata->device_nr = id;
			return 1;
		}
	}
	return 0;
}
static int v4l2loopback_lookup(int device_nr, struct v4l2_loopback_device **device)
{
	struct v4l2loopback_lookup_cb_data data = {
		.device_nr = device_nr, .device = NULL, };

	int err = idr_for_each(&v4l2loopback_index_idr, &v4l2loopback_lookup_cb, &data);
	if (1 == err) {
		if (device)
			*device = data.device;
		return data.device_nr;
	}
	return -ENODEV;
}
static struct v4l2_loopback_device *v4l2loopback_cd2dev(struct device *cd)
{
	struct video_device *loopdev = to_video_device(cd);
	struct v4l2loopback_private *ptr = (struct v4l2loopback_private *)video_get_drvdata(loopdev);
	int nr = ptr->device_nr;

	return idr_find(&v4l2loopback_index_idr, nr);
}

static struct v4l2_loopback_device *v4l2loopback_getdevice(struct file *f)
{
	struct v4l2loopback_private *ptr = video_drvdata(f);
	int nr = ptr->device_nr;

	return idr_find(&v4l2loopback_index_idr, nr);
}


static void init_buffers(struct v4l2_loopback_device *dev);
static int allocate_buffers(struct v4l2_loopback_device *dev);
static void free_buffers(struct v4l2_loopback_device *dev);
static void try_free_buffers(struct v4l2_loopback_device *dev);
static int allocate_timeout_image(struct v4l2_loopback_device *dev);
static void check_timers(struct v4l2_loopback_device *dev);
static const struct v4l2_file_operations v4l2_loopback_fops;
static const struct v4l2_ioctl_ops v4l2_loopback_ioctl_ops;



static inline void set_done(struct v4l2l_buffer *buffer)
{
	buffer->buffer.flags &= ~V4L2_BUF_FLAG_QUEUED;
	buffer->buffer.flags |= V4L2_BUF_FLAG_DONE;
}

static inline void set_queued(struct v4l2l_buffer *buffer)
{
	buffer->buffer.flags &= ~V4L2_BUF_FLAG_DONE;
	buffer->buffer.flags |= V4L2_BUF_FLAG_QUEUED;
}

static inline void unset_flags(struct v4l2l_buffer *buffer)
{
	buffer->buffer.flags &= ~V4L2_BUF_FLAG_QUEUED;
	buffer->buffer.flags &= ~V4L2_BUF_FLAG_DONE;
}



static int vidioc_querycap(struct file *file, void *priv, struct v4l2_capability *cap)
{
	struct v4l2_loopback_device *dev = v4l2loopback_getdevice(file);
	int labellen = (sizeof(cap->card) < sizeof(dev->card_label)) ? sizeof(cap->card) :
				     sizeof(dev->card_label);
	int device_nr = ((struct v4l2loopback_private *)video_get_drvdata(dev->vdev))
			->device_nr;
	__u32 capabilities = V4L2_CAP_STREAMING | V4L2_CAP_READWRITE;

	strlcpy(cap->driver, "v4l2 loopback", sizeof(cap->driver));
	snprintf(cap->card, labellen, dev->card_label);
	snprintf(cap->bus_info, sizeof(cap->bus_info), "platform:v4l2loopback-%03d", device_nr);


	
	cap->version = V4L2LOOPBACK_VERSION_CODE;



	capabilities |= V4L2_CAP_VIDEO_M2M;


	if (dev->announce_all_caps) {
		capabilities |= V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_VIDEO_OUTPUT;
	} else {
		if (dev->ready_for_capture) {
			capabilities |= V4L2_CAP_VIDEO_CAPTURE;
		}
		if (dev->ready_for_output) {
			capabilities |= V4L2_CAP_VIDEO_OUTPUT;
		}
	}


	dev->vdev->device_caps =  cap->device_caps = cap->capabilities = capabilities;



	cap->capabilities |= V4L2_CAP_DEVICE_CAPS;


	memset(cap->reserved, 0, sizeof(cap->reserved));
	return 0;
}

static int vidioc_enum_framesizes(struct file *file, void *fh, struct v4l2_frmsizeenum *argp)
{
	struct v4l2_loopback_device *dev;

	

	
	if (argp->index)
		return -EINVAL;

	dev = v4l2loopback_getdevice(file);
	if (dev->ready_for_capture) {
		
		argp->type = V4L2_FRMSIZE_TYPE_DISCRETE;

		argp->discrete.width = dev->pix_format.width;
		argp->discrete.height = dev->pix_format.height;
	} else {
		
		argp->type = V4L2_FRMSIZE_TYPE_CONTINUOUS;

		argp->stepwise.min_width = V4L2LOOPBACK_SIZE_MIN_WIDTH;
		argp->stepwise.min_height = V4L2LOOPBACK_SIZE_MIN_HEIGHT;

		argp->stepwise.max_width = dev->max_width;
		argp->stepwise.max_height = dev->max_height;

		argp->stepwise.step_width = 1;
		argp->stepwise.step_height = 1;
	}
	return 0;
}


static int vidioc_enum_frameintervals(struct file *file, void *fh, struct v4l2_frmivalenum *argp)
{
	struct v4l2_loopback_device *dev = v4l2loopback_getdevice(file);
	struct v4l2_loopback_opener *opener = fh_to_opener(fh);

	if (dev->ready_for_capture) {
		if (opener->vidioc_enum_frameintervals_calls > 0)
			return -EINVAL;
		if (argp->width == dev->pix_format.width && argp->height == dev->pix_format.height) {
			argp->type = V4L2_FRMIVAL_TYPE_DISCRETE;
			argp->discrete = dev->capture_param.timeperframe;
			opener->vidioc_enum_frameintervals_calls++;
			return 0;
		}
		return -EINVAL;
	}
	return 0;
}




static int vidioc_enum_fmt_cap(struct file *file, void *fh, struct v4l2_fmtdesc *f)
{
	struct v4l2_loopback_device *dev;
	MARK();

	dev = v4l2loopback_getdevice(file);

	if (f->index)
		return -EINVAL;
	if (dev->ready_for_capture) {
		const __u32 format = dev->pix_format.pixelformat;

		snprintf(f->description, sizeof(f->description), "[%c%c%c%c]", (format >> 0) & 0xFF, (format >> 8) & 0xFF, (format >> 16) & 0xFF, (format >> 24) & 0xFF);


		f->pixelformat = dev->pix_format.pixelformat;
	} else {
		return -EINVAL;
	}
	f->flags = 0;
	MARK();
	return 0;
}


static int vidioc_g_fmt_cap(struct file *file, void *priv, struct v4l2_format *fmt)
{
	struct v4l2_loopback_device *dev;
	MARK();

	dev = v4l2loopback_getdevice(file);

	if (!dev->ready_for_capture)
		return -EINVAL;

	fmt->fmt.pix = dev->pix_format;
	MARK();
	return 0;
}


static int vidioc_try_fmt_cap(struct file *file, void *priv, struct v4l2_format *fmt)
{
	struct v4l2_loopback_device *dev;
	char buf[5];

	dev = v4l2loopback_getdevice(file);

	if (0 == dev->ready_for_capture) {
		dprintk("setting fmt_cap not possible yet\n");
		return -EBUSY;
	}

	if (fmt->fmt.pix.pixelformat != dev->pix_format.pixelformat)
		return -EINVAL;

	fmt->fmt.pix = dev->pix_format;

	buf[4] = 0;
	dprintk("capFOURCC=%s\n", fourcc2str(dev->pix_format.pixelformat, buf));
	return 0;
}


static int vidioc_s_fmt_cap(struct file *file, void *priv, struct v4l2_format *fmt)
{
	return vidioc_try_fmt_cap(file, priv, fmt);
}




static int vidioc_enum_fmt_out(struct file *file, void *fh, struct v4l2_fmtdesc *f)
{
	struct v4l2_loopback_device *dev;
	const struct v4l2l_format *fmt;

	dev = v4l2loopback_getdevice(file);

	if (dev->ready_for_capture) {
		const __u32 format = dev->pix_format.pixelformat;

		
		if (f->index)
			return -EINVAL;

		fmt = format_by_fourcc(format);
		if (NULL == fmt)
			return -EINVAL;

		f->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		
		snprintf(f->description, sizeof(f->description), "%s", fmt->name);

		f->pixelformat = dev->pix_format.pixelformat;
	} else {
		
		
		if (f->index < 0 || f->index >= FORMATS)
			return -EINVAL;

		fmt = &formats[f->index];

		f->pixelformat = fmt->fourcc;
		snprintf(f->description, sizeof(f->description), "%s", fmt->name);
	}
	f->flags = 0;

	return 0;
}



static int vidioc_g_fmt_out(struct file *file, void *priv, struct v4l2_format *fmt)
{
	struct v4l2_loopback_device *dev;
	MARK();

	dev = v4l2loopback_getdevice(file);

	

	fmt->fmt.pix = dev->pix_format;
	return 0;
}


static int vidioc_try_fmt_out(struct file *file, void *priv, struct v4l2_format *fmt)
{
	struct v4l2_loopback_device *dev;
	MARK();

	dev = v4l2loopback_getdevice(file);

	
	if (dev->ready_for_capture) {
		fmt->fmt.pix = dev->pix_format;
	} else {
		__u32 w = fmt->fmt.pix.width;
		__u32 h = fmt->fmt.pix.height;
		__u32 pixfmt = fmt->fmt.pix.pixelformat;
		const struct v4l2l_format *format = format_by_fourcc(pixfmt);

		if (w > dev->max_width)
			w = dev->max_width;
		if (h > dev->max_height)
			h = dev->max_height;

		dprintk("trying image %dx%d\n", w, h);

		if (w < 1)
			w = V4L2LOOPBACK_SIZE_DEFAULT_WIDTH;

		if (h < 1)
			h = V4L2LOOPBACK_SIZE_DEFAULT_HEIGHT;

		if (NULL == format)
			format = &formats[0];

		pix_format_set_size(&fmt->fmt.pix, format, w, h);

		fmt->fmt.pix.pixelformat = format->fourcc;

		if ((fmt->fmt.pix.colorspace == V4L2_COLORSPACE_DEFAULT) || (fmt->fmt.pix.colorspace > V4L2_COLORSPACE_DCI_P3))
			fmt->fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;

		if (V4L2_FIELD_ANY == fmt->fmt.pix.field)
			fmt->fmt.pix.field = V4L2_FIELD_NONE;

		
		dev->pix_format = fmt->fmt.pix;
	}
	return 0;
}


static int vidioc_s_fmt_out(struct file *file, void *priv, struct v4l2_format *fmt)
{
	struct v4l2_loopback_device *dev;
	char buf[5];
	int ret;
	MARK();

	dev = v4l2loopback_getdevice(file);
	ret = vidioc_try_fmt_out(file, priv, fmt);

	dprintk("s_fmt_out(%d) %d...%d\n", ret, dev->ready_for_capture, dev->pix_format.sizeimage);

	buf[4] = 0;
	dprintk("outFOURCC=%s\n", fourcc2str(dev->pix_format.pixelformat, buf));

	if (ret < 0)
		return ret;

	if (!dev->ready_for_capture) {
		dev->buffer_size = PAGE_ALIGN(dev->pix_format.sizeimage);
		fmt->fmt.pix.sizeimage = dev->buffer_size;
		allocate_buffers(dev);
	}
	return ret;
}







static int vidioc_g_fmt_overlay(struct file *file, void *priv, struct v4l2_format *fmt)
{
	return 0;
}

static int vidioc_s_fmt_overlay(struct file *file, void *priv, struct v4l2_format *fmt)
{
	return 0;
}





static int vidioc_g_parm(struct file *file, void *priv, struct v4l2_streamparm *parm)
{
	
	struct v4l2_loopback_device *dev;
	MARK();

	dev = v4l2loopback_getdevice(file);
	parm->parm.capture = dev->capture_param;
	return 0;
}


static int vidioc_s_parm(struct file *file, void *priv, struct v4l2_streamparm *parm)
{
	struct v4l2_loopback_device *dev;
	int err = 0;
	MARK();

	dev = v4l2loopback_getdevice(file);
	dprintk("vidioc_s_parm called frate=%d/%d\n", parm->parm.capture.timeperframe.numerator, parm->parm.capture.timeperframe.denominator);


	switch (parm->type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
		if ((err = set_timeperframe( dev, &parm->parm.capture.timeperframe)) < 0)
			return err;
		break;
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		if ((err = set_timeperframe( dev, &parm->parm.capture.timeperframe)) < 0)
			return err;
		break;
	default:
		return -1;
	}

	parm->parm.capture = dev->capture_param;
	return 0;
}



static int vidioc_s_std(struct file *file, void *fh, v4l2_std_id *_std)
{
	v4l2_std_id req_std = 0, supported_std = 0;
	const v4l2_std_id all_std = V4L2_STD_ALL, no_std = 0;

	if (_std) {
		req_std = *_std;
		*_std = all_std;
	}

	
	supported_std = (all_std & req_std);
	if (no_std == supported_std)
		return -EINVAL;

	return 0;
}


static int vidioc_g_std(struct file *file, void *fh, v4l2_std_id *norm)
{
	if (norm)
		*norm = V4L2_STD_ALL;
	return 0;
}

static int vidioc_querystd(struct file *file, void *fh, v4l2_std_id *norm)
{
	if (norm)
		*norm = V4L2_STD_ALL;
	return 0;
}



static int vidioc_queryctrl(struct file *file, void *fh, struct v4l2_queryctrl *q)
{
	const struct v4l2_ctrl_config *cnf = 0;
	switch (q->id) {
	case CID_KEEP_FORMAT:
		cnf = &v4l2loopback_ctrl_keepformat;
		break;
	case CID_SUSTAIN_FRAMERATE:
		cnf = &v4l2loopback_ctrl_sustainframerate;
		break;
	case CID_TIMEOUT:
		cnf = &v4l2loopback_ctrl_timeout;
		break;
	case CID_TIMEOUT_IMAGE_IO:
		cnf = &v4l2loopback_ctrl_timeoutimageio;
		break;
	default:
		return -EINVAL;
	}
	if (!cnf)
		BUG();

	strcpy(q->name, cnf->name);
	q->default_value = cnf->def;
	q->type = cnf->type;
	q->minimum = cnf->min;
	q->maximum = cnf->max;
	q->step = cnf->step;

	memset(q->reserved, 0, sizeof(q->reserved));
	return 0;
}

static int vidioc_g_ctrl(struct file *file, void *fh, struct v4l2_control *c)
{
	struct v4l2_loopback_device *dev = v4l2loopback_getdevice(file);

	switch (c->id) {
	case CID_KEEP_FORMAT:
		c->value = dev->keep_format;
		break;
	case CID_SUSTAIN_FRAMERATE:
		c->value = dev->sustain_framerate;
		break;
	case CID_TIMEOUT:
		c->value = jiffies_to_msecs(dev->timeout_jiffies);
		break;
	case CID_TIMEOUT_IMAGE_IO:
		c->value = dev->timeout_image_io;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int v4l2loopback_set_ctrl(struct v4l2_loopback_device *dev, u32 id, s64 val)
{
	switch (id) {
	case CID_KEEP_FORMAT:
		if (val < 0 || val > 1)
			return -EINVAL;
		dev->keep_format = val;
		try_free_buffers( dev);
		break;
	case CID_SUSTAIN_FRAMERATE:
		if (val < 0 || val > 1)
			return -EINVAL;
		spin_lock_bh(&dev->lock);
		dev->sustain_framerate = val;
		check_timers(dev);
		spin_unlock_bh(&dev->lock);
		break;
	case CID_TIMEOUT:
		if (val < 0 || val > MAX_TIMEOUT)
			return -EINVAL;
		spin_lock_bh(&dev->lock);
		dev->timeout_jiffies = msecs_to_jiffies(val);
		check_timers(dev);
		spin_unlock_bh(&dev->lock);
		allocate_timeout_image(dev);
		break;
	case CID_TIMEOUT_IMAGE_IO:
		if (val < 0 || val > 1)
			return -EINVAL;
		dev->timeout_image_io = val;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int v4l2loopback_s_ctrl(struct v4l2_ctrl *ctrl)
{
	struct v4l2_loopback_device *dev = container_of( ctrl->handler, struct v4l2_loopback_device, ctrl_handler);
	return v4l2loopback_set_ctrl(dev, ctrl->id, ctrl->val);
}
static int vidioc_s_ctrl(struct file *file, void *fh, struct v4l2_control *c)
{
	struct v4l2_loopback_device *dev = v4l2loopback_getdevice(file);
	return v4l2loopback_set_ctrl(dev, c->id, c->value);
}


static int vidioc_enum_output(struct file *file, void *fh, struct v4l2_output *outp)
{
	__u32 index = outp->index;
	struct v4l2_loopback_device *dev = v4l2loopback_getdevice(file);
	MARK();

	if (!dev->announce_all_caps && !dev->ready_for_output)
		return -ENOTTY;

	if (0 != index)
		return -EINVAL;

	
	memset(outp, 0, sizeof(*outp));

	outp->index = index;
	strlcpy(outp->name, "loopback in", sizeof(outp->name));
	outp->type = V4L2_OUTPUT_TYPE_ANALOG;
	outp->audioset = 0;
	outp->modulator = 0;

	outp->std = V4L2_STD_ALL;

	outp->capabilities |= V4L2_OUT_CAP_STD;



	return 0;
}


static int vidioc_g_output(struct file *file, void *fh, unsigned int *i)
{
	struct v4l2_loopback_device *dev = v4l2loopback_getdevice(file);
	if (!dev->announce_all_caps && !dev->ready_for_output)
		return -ENOTTY;
	if (i)
		*i = 0;
	return 0;
}


static int vidioc_s_output(struct file *file, void *fh, unsigned int i)
{
	struct v4l2_loopback_device *dev = v4l2loopback_getdevice(file);
	if (!dev->announce_all_caps && !dev->ready_for_output)
		return -ENOTTY;

	if (i)
		return -EINVAL;

	return 0;
}


static int vidioc_enum_input(struct file *file, void *fh, struct v4l2_input *inp)
{
	__u32 index = inp->index;
	MARK();

	if (0 != index)
		return -EINVAL;

	
	memset(inp, 0, sizeof(*inp));

	inp->index = index;
	strlcpy(inp->name, "loopback", sizeof(inp->name));
	inp->type = V4L2_INPUT_TYPE_CAMERA;
	inp->audioset = 0;
	inp->tuner = 0;
	inp->status = 0;


	inp->std = V4L2_STD_ALL;

	inp->capabilities |= V4L2_IN_CAP_STD;



	return 0;
}


static int vidioc_g_input(struct file *file, void *fh, unsigned int *i)
{
	struct v4l2_loopback_device *dev = v4l2loopback_getdevice(file);
	if (!dev->announce_all_caps && !dev->ready_for_capture)
		return -ENOTTY;
	if (i)
		*i = 0;
	return 0;
}


static int vidioc_s_input(struct file *file, void *fh, unsigned int i)
{
	struct v4l2_loopback_device *dev = v4l2loopback_getdevice(file);
	if (!dev->announce_all_caps && !dev->ready_for_capture)
		return -ENOTTY;
	if (i == 0)
		return 0;
	return -EINVAL;
}




static int vidioc_reqbufs(struct file *file, void *fh, struct v4l2_requestbuffers *b)
{
	struct v4l2_loopback_device *dev;
	struct v4l2_loopback_opener *opener;
	int i;
	MARK();

	dev = v4l2loopback_getdevice(file);
	opener = fh_to_opener(fh);

	dprintk("reqbufs: %d\t%d=%d\n", b->memory, b->count, dev->buffers_number);
	if (opener->timeout_image_io) {
		if (b->memory != V4L2_MEMORY_MMAP)
			return -EINVAL;
		b->count = 1;
		return 0;
	}

	init_buffers(dev);
	switch (b->memory) {
	case V4L2_MEMORY_MMAP:
		
		if (b->count < 1 || dev->buffers_number < 1)
			return 0;

		if (b->count > dev->buffers_number)
			b->count = dev->buffers_number;

		
		if (list_empty(&dev->outbufs_list)) {
			for (i = 0; i < dev->used_buffers; ++i)
				list_add_tail(&dev->buffers[i].list_head, &dev->outbufs_list);
		}

		
		if (b->count < dev->used_buffers) {
			struct v4l2l_buffer *pos, *n;

			list_for_each_entry_safe (pos, n, &dev->outbufs_list, list_head) {
				if (pos->buffer.index >= b->count)
					list_del(&pos->list_head);
			}

			
			i = dev->write_position;
			list_for_each_entry (pos, &dev->outbufs_list, list_head) {
				dev->bufpos2index[i % b->count] = pos->buffer.index;
				++i;
			}
		}

		opener->buffers_number = b->count;
		if (opener->buffers_number < dev->used_buffers)
			dev->used_buffers = opener->buffers_number;
		return 0;
	default:
		return -EINVAL;
	}
}


static int vidioc_querybuf(struct file *file, void *fh, struct v4l2_buffer *b)
{
	enum v4l2_buf_type type;
	int index;
	struct v4l2_loopback_device *dev;
	struct v4l2_loopback_opener *opener;

	MARK();

	type = b->type;
	index = b->index;
	dev = v4l2loopback_getdevice(file);
	opener = fh_to_opener(fh);

	if ((b->type != V4L2_BUF_TYPE_VIDEO_CAPTURE) && (b->type != V4L2_BUF_TYPE_VIDEO_OUTPUT)) {
		return -EINVAL;
	}
	if (b->index > max_buffers)
		return -EINVAL;

	if (opener->timeout_image_io)
		*b = dev->timeout_image_buffer.buffer;
	else *b = dev->buffers[b->index % dev->used_buffers].buffer;

	b->type = type;
	b->index = index;
	dprintkrw("buffer type: %d (of %d with size=%ld)\n", b->memory, dev->buffers_number, dev->buffer_size);

	
	b->flags &= ~V4L2_BUF_FLAG_DONE;
	b->flags |= V4L2_BUF_FLAG_QUEUED;

	return 0;
}

static void buffer_written(struct v4l2_loopback_device *dev, struct v4l2l_buffer *buf)
{
	del_timer_sync(&dev->sustain_timer);
	del_timer_sync(&dev->timeout_timer);
	spin_lock_bh(&dev->lock);

	dev->bufpos2index[dev->write_position % dev->used_buffers] = buf->buffer.index;
	list_move_tail(&buf->list_head, &dev->outbufs_list);
	++dev->write_position;
	dev->reread_count = 0;

	check_timers(dev);
	spin_unlock_bh(&dev->lock);
}


static int vidioc_qbuf(struct file *file, void *fh, struct v4l2_buffer *buf)
{
	struct v4l2_loopback_device *dev;
	struct v4l2_loopback_opener *opener;
	struct v4l2l_buffer *b;
	int index;

	dev = v4l2loopback_getdevice(file);
	opener = fh_to_opener(fh);

	if (buf->index > max_buffers)
		return -EINVAL;
	if (opener->timeout_image_io)
		return 0;

	index = buf->index % dev->used_buffers;
	b = &dev->buffers[index];

	switch (buf->type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
		dprintkrw("capture QBUF index: %d\n", index);
		set_queued(b);
		return 0;
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		dprintkrw("output QBUF pos: %d index: %d\n", dev->write_position, index);
		if (buf->timestamp.tv_sec == 0 && buf->timestamp.tv_usec == 0)
			v4l2l_get_timestamp(&b->buffer);
		else b->buffer.timestamp = buf->timestamp;
		b->buffer.bytesused = buf->bytesused;
		set_done(b);
		buffer_written(dev, b);

		
		buf->flags &= ~V4L2_BUF_FLAG_DONE;
		buf->flags |= V4L2_BUF_FLAG_QUEUED;

		wake_up_all(&dev->read_event);
		return 0;
	default:
		return -EINVAL;
	}
}

static int can_read(struct v4l2_loopback_device *dev, struct v4l2_loopback_opener *opener)
{
	int ret;

	spin_lock_bh(&dev->lock);
	check_timers(dev);
	ret = dev->write_position > opener->read_position || dev->reread_count > opener->reread_count || dev->timeout_happened;
	spin_unlock_bh(&dev->lock);
	return ret;
}

static int get_capture_buffer(struct file *file)
{
	struct v4l2_loopback_device *dev = v4l2loopback_getdevice(file);
	struct v4l2_loopback_opener *opener = fh_to_opener(file->private_data);
	int pos, ret;
	int timeout_happened;

	if ((file->f_flags & O_NONBLOCK) && (dev->write_position <= opener->read_position && dev->reread_count <= opener->reread_count && !dev->timeout_happened))


		return -EAGAIN;
	wait_event_interruptible(dev->read_event, can_read(dev, opener));

	spin_lock_bh(&dev->lock);
	if (dev->write_position == opener->read_position) {
		if (dev->reread_count > opener->reread_count + 2)
			opener->reread_count = dev->reread_count - 1;
		++opener->reread_count;
		pos = (opener->read_position + dev->used_buffers - 1) % dev->used_buffers;
	} else {
		opener->reread_count = 0;
		if (dev->write_position > opener->read_position + dev->used_buffers)
			opener->read_position = dev->write_position - 1;
		pos = opener->read_position % dev->used_buffers;
		++opener->read_position;
	}
	timeout_happened = dev->timeout_happened;
	dev->timeout_happened = 0;
	spin_unlock_bh(&dev->lock);

	ret = dev->bufpos2index[pos];
	if (timeout_happened) {
		if (ret < 0) {
			dprintk("trying to return not mapped buf[%d]\n", ret);
			return -EFAULT;
		}
		
		memcpy(dev->image + dev->buffers[ret].buffer.m.offset, dev->timeout_image, dev->buffer_size);
	}
	return ret;
}


static int vidioc_dqbuf(struct file *file, void *fh, struct v4l2_buffer *buf)
{
	struct v4l2_loopback_device *dev;
	struct v4l2_loopback_opener *opener;
	int index;
	struct v4l2l_buffer *b;

	dev = v4l2loopback_getdevice(file);
	opener = fh_to_opener(fh);
	if (opener->timeout_image_io) {
		*buf = dev->timeout_image_buffer.buffer;
		return 0;
	}

	switch (buf->type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
		index = get_capture_buffer(file);
		if (index < 0)
			return index;
		dprintkrw("capture DQBUF pos: %d index: %d\n", opener->read_position - 1, index);
		if (!(dev->buffers[index].buffer.flags & V4L2_BUF_FLAG_MAPPED)) {
			dprintk("trying to return not mapped buf[%d]\n", index);
			return -EINVAL;
		}
		unset_flags(&dev->buffers[index]);
		*buf = dev->buffers[index].buffer;
		return 0;
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		b = list_entry(dev->outbufs_list.prev, struct v4l2l_buffer, list_head);
		list_move_tail(&b->list_head, &dev->outbufs_list);
		dprintkrw("output DQBUF index: %d\n", b->buffer.index);
		unset_flags(b);
		*buf = b->buffer;
		buf->type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
		return 0;
	default:
		return -EINVAL;
	}
}




static int vidioc_streamon(struct file *file, void *fh, enum v4l2_buf_type type)
{
	struct v4l2_loopback_device *dev;
	struct v4l2_loopback_opener *opener;
	MARK();

	dev = v4l2loopback_getdevice(file);
	opener = fh_to_opener(fh);

	switch (type) {
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		if (!dev->ready_for_capture) {
			int ret = allocate_buffers(dev);
			if (ret < 0)
				return ret;
		}
		opener->type = WRITER;
		dev->ready_for_output = 0;
		dev->ready_for_capture++;
		return 0;
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
		if (!dev->ready_for_capture)
			return -EIO;
		opener->type = READER;
		return 0;
	default:
		return -EINVAL;
	}
	return -EINVAL;
}


static int vidioc_streamoff(struct file *file, void *fh, enum v4l2_buf_type type)
{
	struct v4l2_loopback_device *dev;
	MARK();
	dprintk("%d\n", type);

	dev = v4l2loopback_getdevice(file);

	switch (type) {
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		if (dev->ready_for_capture > 0)
			dev->ready_for_capture--;
		return 0;
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
		return 0;
	default:
		return -EINVAL;
	}
	return -EINVAL;
}


static int vidiocgmbuf(struct file *file, void *fh, struct video_mbuf *p)
{
	struct v4l2_loopback_device *dev;
	MARK();

	dev = v4l2loopback_getdevice(file);
	p->frames = dev->buffers_number;
	p->offsets[0] = 0;
	p->offsets[1] = 0;
	p->size = dev->buffer_size;
	return 0;
}


static int vidioc_subscribe_event(struct v4l2_fh *fh, const struct v4l2_event_subscription *sub)
{
	switch (sub->type) {
	case V4L2_EVENT_CTRL:
		return v4l2_ctrl_subscribe_event(fh, sub);
	}

	return -EINVAL;
}


static void vm_open(struct vm_area_struct *vma)
{
	struct v4l2l_buffer *buf;
	MARK();

	buf = vma->vm_private_data;
	buf->use_count++;
}

static void vm_close(struct vm_area_struct *vma)
{
	struct v4l2l_buffer *buf;
	MARK();

	buf = vma->vm_private_data;
	buf->use_count--;
}

static struct vm_operations_struct vm_ops = {
	.open = vm_open, .close = vm_close, };


static int v4l2_loopback_mmap(struct file *file, struct vm_area_struct *vma)
{
	u8 *addr;
	unsigned long start;
	unsigned long size;
	struct v4l2_loopback_device *dev;
	struct v4l2_loopback_opener *opener;
	struct v4l2l_buffer *buffer = NULL;
	MARK();

	start = (unsigned long)vma->vm_start;
	size = (unsigned long)(vma->vm_end - vma->vm_start);

	dev = v4l2loopback_getdevice(file);
	opener = fh_to_opener(file->private_data);

	if (size > dev->buffer_size) {
		dprintk("userspace tries to mmap too much, fail\n");
		return -EINVAL;
	}
	if (opener->timeout_image_io) {
		
		if ((vma->vm_pgoff << PAGE_SHIFT) != dev->buffer_size * MAX_BUFFERS) {
			dprintk("invalid mmap offset for timeout_image_io mode\n");
			return -EINVAL;
		}
	} else if ((vma->vm_pgoff << PAGE_SHIFT) > dev->buffer_size * (dev->buffers_number - 1)) {
		dprintk("userspace tries to mmap too far, fail\n");
		return -EINVAL;
	}

	
	if (NULL == dev->image)
		if (allocate_buffers(dev) < 0)
			return -EINVAL;

	if (opener->timeout_image_io) {
		buffer = &dev->timeout_image_buffer;
		addr = dev->timeout_image;
	} else {
		int i;
		for (i = 0; i < dev->buffers_number; ++i) {
			buffer = &dev->buffers[i];
			if ((buffer->buffer.m.offset >> PAGE_SHIFT) == vma->vm_pgoff)
				break;
		}

		if (NULL == buffer)
			return -EINVAL;

		addr = dev->image + (vma->vm_pgoff << PAGE_SHIFT);
	}

	while (size > 0) {
		struct page *page;

		page = vmalloc_to_page(addr);

		if (vm_insert_page(vma, start, page) < 0)
			return -EAGAIN;

		start += PAGE_SIZE;
		addr += PAGE_SIZE;
		size -= PAGE_SIZE;
	}

	vma->vm_ops = &vm_ops;
	vma->vm_private_data = buffer;
	buffer->buffer.flags |= V4L2_BUF_FLAG_MAPPED;

	vm_open(vma);

	MARK();
	return 0;
}

static unsigned int v4l2_loopback_poll(struct file *file, struct poll_table_struct *pts)
{
	struct v4l2_loopback_opener *opener;
	struct v4l2_loopback_device *dev;
	__poll_t req_events = poll_requested_events(pts);
	int ret_mask = 0;
	MARK();

	opener = fh_to_opener(file->private_data);
	dev = v4l2loopback_getdevice(file);

	if (req_events & POLLPRI) {
		if (!v4l2_event_pending(&opener->fh))
			poll_wait(file, &opener->fh.wait, pts);
		if (v4l2_event_pending(&opener->fh)) {
			ret_mask |= POLLPRI;
			if (!(req_events & DEFAULT_POLLMASK))
				return ret_mask;
		}
	}

	switch (opener->type) {
	case WRITER:
		ret_mask |= POLLOUT | POLLWRNORM;
		break;
	case READER:
		if (!can_read(dev, opener)) {
			if (ret_mask)
				return ret_mask;
			poll_wait(file, &dev->read_event, pts);
		}
		if (can_read(dev, opener))
			ret_mask |= POLLIN | POLLRDNORM;
		if (v4l2_event_pending(&opener->fh))
			ret_mask |= POLLPRI;
		break;
	default:
		break;
	}

	MARK();
	return ret_mask;
}


static int v4l2_loopback_open(struct file *file)
{
	struct v4l2_loopback_device *dev;
	struct v4l2_loopback_opener *opener;
	MARK();
	dev = v4l2loopback_getdevice(file);
	if (dev->open_count.counter >= dev->max_openers)
		return -EBUSY;
	
	opener = kzalloc(sizeof(*opener), GFP_KERNEL);
	if (opener == NULL)
		return -ENOMEM;

	atomic_inc(&dev->open_count);

	opener->timeout_image_io = dev->timeout_image_io;
	if (opener->timeout_image_io) {
		int r = allocate_timeout_image(dev);

		if (r < 0) {
			dprintk("timeout image allocation failed\n");

			atomic_dec(&dev->open_count);

			kfree(opener);
			return r;
		}
	}

	dev->timeout_image_io = 0;

	v4l2_fh_init(&opener->fh, video_devdata(file));
	file->private_data = &opener->fh;

	v4l2_fh_add(&opener->fh);
	dprintk("opened dev:%p with image:%p\n", dev, dev ? dev->image : NULL);
	MARK();
	return 0;
}

static int v4l2_loopback_close(struct file *file)
{
	struct v4l2_loopback_opener *opener;
	struct v4l2_loopback_device *dev;
	int iswriter = 0;
	MARK();

	opener = fh_to_opener(file->private_data);
	dev = v4l2loopback_getdevice(file);

	if (WRITER == opener->type)
		iswriter = 1;

	atomic_dec(&dev->open_count);
	if (dev->open_count.counter == 0) {
		del_timer_sync(&dev->sustain_timer);
		del_timer_sync(&dev->timeout_timer);
	}
	try_free_buffers(dev);

	v4l2_fh_del(&opener->fh);
	v4l2_fh_exit(&opener->fh);

	kfree(opener);
	if (iswriter) {
		dev->ready_for_output = 1;
	}
	MARK();
	return 0;
}

static ssize_t v4l2_loopback_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int read_index;
	struct v4l2_loopback_device *dev;
	struct v4l2_buffer *b;
	MARK();

	dev = v4l2loopback_getdevice(file);

	read_index = get_capture_buffer(file);
	if (read_index < 0)
		return read_index;
	if (count > dev->buffer_size)
		count = dev->buffer_size;
	b = &dev->buffers[read_index].buffer;
	if (count > b->bytesused)
		count = b->bytesused;
	if (copy_to_user((void *)buf, (void *)(dev->image + b->m.offset), count)) {
		printk(KERN_ERR "v4l2-loopback: failed copy_to_user() in read buf\n");
		return -EFAULT;
	}
	dprintkrw("leave v4l2_loopback_read()\n");
	return count;
}

static ssize_t v4l2_loopback_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct v4l2_loopback_opener *opener;
	struct v4l2_loopback_device *dev;
	int write_index;
	struct v4l2_buffer *b;
	int err = 0;

	MARK();

	dev = v4l2loopback_getdevice(file);
	opener = fh_to_opener(file->private_data);

	if (UNNEGOTIATED == opener->type) {
		spin_lock(&dev->lock);

		if (dev->ready_for_output) {
			err = vidioc_streamon(file, file->private_data, V4L2_BUF_TYPE_VIDEO_OUTPUT);
		}

		spin_unlock(&dev->lock);

		if (err < 0)
			return err;
	}

	if (WRITER != opener->type)
		return -EINVAL;

	if (!dev->ready_for_capture) {
		int ret = allocate_buffers(dev);
		if (ret < 0)
			return ret;
		dev->ready_for_capture = 1;
	}
	dprintkrw("v4l2_loopback_write() trying to write %zu bytes\n", count);
	if (count > dev->buffer_size)
		count = dev->buffer_size;

	write_index = dev->write_position % dev->used_buffers;
	b = &dev->buffers[write_index].buffer;

	if (copy_from_user((void *)(dev->image + b->m.offset), (void *)buf, count)) {
		printk(KERN_ERR "v4l2-loopback: failed copy_from_user() in write buf, could not write %zu\n", count);

		return -EFAULT;
	}
	v4l2l_get_timestamp(b);
	b->bytesused = count;
	b->sequence = dev->write_position;
	buffer_written(dev, &dev->buffers[write_index]);
	wake_up_all(&dev->read_event);
	dprintkrw("leave v4l2_loopback_write()\n");
	return count;
}



static void free_buffers(struct v4l2_loopback_device *dev)
{
	MARK();
	dprintk("freeing image@%p for dev:%p\n", dev ? dev->image : NULL, dev);
	if (dev->image) {
		vfree(dev->image);
		dev->image = NULL;
	}
	if (dev->timeout_image) {
		vfree(dev->timeout_image);
		dev->timeout_image = NULL;
	}
	dev->imagesize = 0;
}

static void try_free_buffers(struct v4l2_loopback_device *dev)
{
	MARK();
	if (0 == dev->open_count.counter && !dev->keep_format) {
		free_buffers(dev);
		dev->ready_for_capture = 0;
		dev->buffer_size = 0;
		dev->write_position = 0;
	}
}

static int allocate_buffers(struct v4l2_loopback_device *dev)
{
	int err;

	MARK();
	

	if (dev->buffer_size < 1 || dev->buffers_number < 1)
		return -EINVAL;

	if ((__LONG_MAX__ / dev->buffer_size) < dev->buffers_number)
		return -ENOSPC;

	if (dev->image) {
		dprintk("allocating buffers again: %ld %ld\n", dev->buffer_size * dev->buffers_number, dev->imagesize);
		
		if (dev->buffer_size * dev->buffers_number == dev->imagesize)
			return 0;

		
		if (dev->open_count.counter == 1)
			free_buffers(dev);
		else return -EINVAL;
	}

	dev->imagesize = (unsigned long)dev->buffer_size * (unsigned long)dev->buffers_number;

	dprintk("allocating %ld = %ldx%d\n", dev->imagesize, dev->buffer_size, dev->buffers_number);
	err = -ENOMEM;

	if (dev->timeout_jiffies > 0) {
		err = allocate_timeout_image(dev);
		if (err < 0)
			goto error;
	}

	dev->image = vmalloc(dev->imagesize);
	if (dev->image == NULL)
		goto error;

	dprintk("vmallocated %ld bytes\n", dev->imagesize);
	MARK();

	init_buffers(dev);
	return 0;

error:
	free_buffers(dev);
	return err;
}


static void init_buffers(struct v4l2_loopback_device *dev)
{
	int i;
	int buffer_size;
	int bytesused;
	MARK();

	buffer_size = dev->buffer_size;
	bytesused = dev->pix_format.sizeimage;

	for (i = 0; i < dev->buffers_number; ++i) {
		struct v4l2_buffer *b = &dev->buffers[i].buffer;
		b->index = i;
		b->bytesused = bytesused;
		b->length = buffer_size;
		b->field = V4L2_FIELD_NONE;
		b->flags = 0;

		b->input = 0;

		b->m.offset = i * buffer_size;
		b->memory = V4L2_MEMORY_MMAP;
		b->sequence = 0;
		b->timestamp.tv_sec = 0;
		b->timestamp.tv_usec = 0;
		b->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

		v4l2l_get_timestamp(b);
	}
	dev->timeout_image_buffer = dev->buffers[0];
	dev->timeout_image_buffer.buffer.m.offset = MAX_BUFFERS * buffer_size;
	MARK();
}

static int allocate_timeout_image(struct v4l2_loopback_device *dev)
{
	MARK();
	if (dev->buffer_size <= 0)
		return -EINVAL;

	if (dev->timeout_image == NULL) {
		dev->timeout_image = v4l2l_vzalloc(dev->buffer_size);
		if (dev->timeout_image == NULL)
			return -ENOMEM;
	}
	return 0;
}


static void init_vdev(struct video_device *vdev, int nr)
{
	MARK();


	vdev->tvnorms = V4L2_STD_ALL;


	vdev->vfl_type = VFL_TYPE_VIDEO;
	vdev->fops = &v4l2_loopback_fops;
	vdev->ioctl_ops = &v4l2_loopback_ioctl_ops;
	vdev->release = &video_device_release;
	vdev->minor = -1;

	vdev->device_caps = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_VIDEO_OUTPUT | V4L2_CAP_READWRITE | V4L2_CAP_STREAMING;

	vdev->device_caps |= V4L2_CAP_VIDEO_M2M;



	if (debug > 1)

		vdev->debug = V4L2_DEBUG_IOCTL | V4L2_DEBUG_IOCTL_ARG;

		vdev->dev_debug = V4L2_DEV_DEBUG_IOCTL | V4L2_DEV_DEBUG_IOCTL_ARG;


		

	vdev->vfl_dir = VFL_DIR_M2M;


	MARK();
}


static void init_capture_param(struct v4l2_captureparm *capture_param)
{
	MARK();
	capture_param->capability = 0;
	capture_param->capturemode = 0;
	capture_param->extendedmode = 0;
	capture_param->readbuffers = max_buffers;
	capture_param->timeperframe.numerator = 1;
	capture_param->timeperframe.denominator = 30;
}

static void check_timers(struct v4l2_loopback_device *dev)
{
	if (!dev->ready_for_capture)
		return;

	if (dev->timeout_jiffies > 0 && !timer_pending(&dev->timeout_timer))
		mod_timer(&dev->timeout_timer, jiffies + dev->timeout_jiffies);
	if (dev->sustain_framerate && !timer_pending(&dev->sustain_timer))
		mod_timer(&dev->sustain_timer, jiffies + dev->frame_jiffies * 3 / 2);
}

static void sustain_timer_clb(struct timer_list *t)
{
	struct v4l2_loopback_device *dev = from_timer(dev, t, sustain_timer);

static void sustain_timer_clb(unsigned long nr)
{
	struct v4l2_loopback_device *dev = idr_find(&v4l2loopback_index_idr, nr);

	spin_lock(&dev->lock);
	if (dev->sustain_framerate) {
		dev->reread_count++;
		dprintkrw("reread: %d %d\n", dev->write_position, dev->reread_count);
		if (dev->reread_count == 1)
			mod_timer(&dev->sustain_timer, jiffies + max(1UL, dev->frame_jiffies / 2));
		else mod_timer(&dev->sustain_timer, jiffies + dev->frame_jiffies);

		wake_up_all(&dev->read_event);
	}
	spin_unlock(&dev->lock);
}

static void timeout_timer_clb(struct timer_list *t)
{
	struct v4l2_loopback_device *dev = from_timer(dev, t, timeout_timer);

static void timeout_timer_clb(unsigned long nr)
{
	struct v4l2_loopback_device *dev = idr_find(&v4l2loopback_index_idr, nr);

	spin_lock(&dev->lock);
	if (dev->timeout_jiffies > 0) {
		dev->timeout_happened = 1;
		mod_timer(&dev->timeout_timer, jiffies + dev->timeout_jiffies);
		wake_up_all(&dev->read_event);
	}
	spin_unlock(&dev->lock);
}







static int v4l2_loopback_add(struct v4l2_loopback_config *conf, int *ret_nr)
{
	struct v4l2_loopback_device *dev;
	struct v4l2_ctrl_handler *hdl;
	struct v4l2loopback_private *vdev_priv = NULL;

	int err = -ENOMEM;

	int _max_width = DEFAULT_FROM_CONF( max_width, < V4L2LOOPBACK_SIZE_MIN_WIDTH, max_width);
	int _max_height = DEFAULT_FROM_CONF( max_height, < V4L2LOOPBACK_SIZE_MIN_HEIGHT, max_height);
	bool _announce_all_caps = (conf && conf->announce_all_caps >= 0) ? (conf->announce_all_caps) :
						V4L2LOOPBACK_DEFAULT_EXCLUSIVECAPS;
	int _max_buffers = DEFAULT_FROM_CONF(max_buffers, <= 0, max_buffers);
	int _max_openers = DEFAULT_FROM_CONF(max_openers, <= 0, max_openers);

	int nr = -1;

	_announce_all_caps = (!!_announce_all_caps);

	if (conf) {
		if (conf->capture_nr >= 0 && conf->output_nr == conf->capture_nr) {
			nr = conf->capture_nr;
		} else if (conf->capture_nr < 0 && conf->output_nr < 0) {
			nr = -1;
		} else if (conf->capture_nr < 0) {
			nr = conf->output_nr;
		} else if (conf->output_nr < 0) {
			nr = conf->capture_nr;
		} else {
			printk(KERN_ERR "split OUTPUT and CAPTURE devices not yet supported.");
			printk(KERN_INFO "both devices must have the same number (%d != %d).", conf->output_nr, conf->capture_nr);

			return -EINVAL;
		}
	}

	if (idr_find(&v4l2loopback_index_idr, nr))
		return -EEXIST;

	dprintk("creating v4l2loopback-device #%d\n", nr);
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	
	if (nr >= 0) {
		err = idr_alloc(&v4l2loopback_index_idr, dev, nr, nr + 1, GFP_KERNEL);
		if (err == -ENOSPC)
			err = -EEXIST;
	} else {
		err = idr_alloc(&v4l2loopback_index_idr, dev, 0, 0, GFP_KERNEL);
	}
	if (err < 0)
		goto out_free_dev;
	nr = err;
	err = -ENOMEM;

	if (conf && conf->card_label && *(conf->card_label)) {
		snprintf(dev->card_label, sizeof(dev->card_label), "%s", conf->card_label);
	} else {
		snprintf(dev->card_label, sizeof(dev->card_label), "Dummy video device (0x%04X)", nr);
	}
	snprintf(dev->v4l2_dev.name, sizeof(dev->v4l2_dev.name), "v4l2loopback-%03d", nr);

	err = v4l2_device_register(NULL, &dev->v4l2_dev);
	if (err)
		goto out_free_idr;
	MARK();

	dev->vdev = video_device_alloc();
	if (dev->vdev == NULL) {
		err = -ENOMEM;
		goto out_unregister;
	}

	vdev_priv = kzalloc(sizeof(struct v4l2loopback_private), GFP_KERNEL);
	if (vdev_priv == NULL) {
		err = -ENOMEM;
		goto out_unregister;
	}

	video_set_drvdata(dev->vdev, vdev_priv);
	if (video_get_drvdata(dev->vdev) == NULL) {
		err = -ENOMEM;
		goto out_unregister;
	}

	MARK();
	snprintf(dev->vdev->name, sizeof(dev->vdev->name), dev->card_label);

	vdev_priv->device_nr = nr;

	init_vdev(dev->vdev, nr);
	dev->vdev->v4l2_dev = &dev->v4l2_dev;
	init_capture_param(&dev->capture_param);
	err = set_timeperframe(dev, &dev->capture_param.timeperframe);
	if (err)
		goto out_unregister;
	dev->keep_format = 0;
	dev->sustain_framerate = 0;

	dev->announce_all_caps = _announce_all_caps;
	dev->max_width = _max_width;
	dev->max_height = _max_height;
	dev->max_openers = _max_openers;
	dev->buffers_number = dev->used_buffers = _max_buffers;

	dev->write_position = 0;

	MARK();
	spin_lock_init(&dev->lock);
	INIT_LIST_HEAD(&dev->outbufs_list);
	if (list_empty(&dev->outbufs_list)) {
		int i;

		for (i = 0; i < dev->used_buffers; ++i)
			list_add_tail(&dev->buffers[i].list_head, &dev->outbufs_list);
	}
	memset(dev->bufpos2index, 0, sizeof(dev->bufpos2index));
	atomic_set(&dev->open_count, 0);
	dev->ready_for_capture = 0;
	dev->ready_for_output = 1;

	dev->buffer_size = 0;
	dev->image = NULL;
	dev->imagesize = 0;

	timer_setup(&dev->sustain_timer, sustain_timer_clb, 0);
	timer_setup(&dev->timeout_timer, timeout_timer_clb, 0);

	setup_timer(&dev->sustain_timer, sustain_timer_clb, nr);
	setup_timer(&dev->timeout_timer, timeout_timer_clb, nr);

	dev->reread_count = 0;
	dev->timeout_jiffies = 0;
	dev->timeout_image = NULL;
	dev->timeout_happened = 0;

	hdl = &dev->ctrl_handler;
	err = v4l2_ctrl_handler_init(hdl, 4);
	if (err)
		goto out_unregister;
	v4l2_ctrl_new_custom(hdl, &v4l2loopback_ctrl_keepformat, NULL);
	v4l2_ctrl_new_custom(hdl, &v4l2loopback_ctrl_sustainframerate, NULL);
	v4l2_ctrl_new_custom(hdl, &v4l2loopback_ctrl_timeout, NULL);
	v4l2_ctrl_new_custom(hdl, &v4l2loopback_ctrl_timeoutimageio, NULL);
	if (hdl->error) {
		err = hdl->error;
		goto out_free_handler;
	}
	dev->v4l2_dev.ctrl_handler = hdl;

	err = v4l2_ctrl_handler_setup(hdl);
	if (err)
		goto out_free_handler;

	

	
	dev->pix_format.width = 0; 
	dev->pix_format.height = 0; 
	dev->pix_format.pixelformat = formats[0].fourcc;
	dev->pix_format.colorspace = V4L2_COLORSPACE_SRGB;
	dev->pix_format.field = V4L2_FIELD_NONE;

	dev->buffer_size = PAGE_ALIGN(dev->pix_format.sizeimage);
	dprintk("buffer_size = %ld (=%d)\n", dev->buffer_size, dev->pix_format.sizeimage);

	if (dev->buffer_size && ((err = allocate_buffers(dev)) < 0))
		goto out_free_handler;

	init_waitqueue_head(&dev->read_event);

	
	if (video_register_device(dev->vdev, VFL_TYPE_VIDEO, nr) < 0) {
		printk(KERN_ERR "v4l2loopback: failed video_register_device()\n");
		err = -EFAULT;
		goto out_free_device;
	}
	v4l2loopback_create_sysfs(dev->vdev);

	MARK();
	if (ret_nr)
		*ret_nr = dev->vdev->num;
	return 0;

out_free_device:
	video_device_release(dev->vdev);
out_free_handler:
	v4l2_ctrl_handler_free(&dev->ctrl_handler);
out_unregister:
	video_set_drvdata(dev->vdev, NULL);
	if (vdev_priv != NULL)
		kfree(vdev_priv);
	v4l2_device_unregister(&dev->v4l2_dev);
out_free_idr:
	idr_remove(&v4l2loopback_index_idr, nr);
out_free_dev:
	kfree(dev);
	return err;
}

static void v4l2_loopback_remove(struct v4l2_loopback_device *dev)
{
	free_buffers(dev);
	v4l2loopback_remove_sysfs(dev->vdev);
	kfree(video_get_drvdata(dev->vdev));
	video_unregister_device(dev->vdev);
	v4l2_device_unregister(&dev->v4l2_dev);
	v4l2_ctrl_handler_free(&dev->ctrl_handler);
	kfree(dev);
}

static long v4l2loopback_control_ioctl(struct file *file, unsigned int cmd, unsigned long parm)
{
	struct v4l2_loopback_device *dev;
	struct v4l2_loopback_config conf;
	struct v4l2_loopback_config *confptr = &conf;
	int device_nr;
	int ret;

	ret = mutex_lock_killable(&v4l2loopback_ctl_mutex);
	if (ret)
		return ret;

	ret = -EINVAL;
	switch (cmd) {
	default:
		ret = -ENOSYS;
		break;
		
	case V4L2LOOPBACK_CTL_ADD:
		if (parm) {
			if ((ret = copy_from_user(&conf, (void *)parm, sizeof(conf))) < 0)
				break;
		} else confptr = NULL;
		ret = v4l2_loopback_add(confptr, &device_nr);
		if (ret >= 0)
			ret = device_nr;
		break;
		
	case V4L2LOOPBACK_CTL_REMOVE:
		ret = v4l2loopback_lookup((int)parm, &dev);
		if (ret >= 0 && dev) {
			int nr = ret;
			ret = -EBUSY;
			if (dev->open_count.counter > 0)
				break;
			idr_remove(&v4l2loopback_index_idr, nr);
			v4l2_loopback_remove(dev);
			ret = 0;
		};
		break;
		
	case V4L2LOOPBACK_CTL_QUERY:
		if (!parm)
			break;
		if ((ret = copy_from_user(&conf, (void *)parm, sizeof(conf))) < 0)
			break;
		device_nr = (conf.output_nr < 0) ? conf.capture_nr : conf.output_nr;
		MARK();
		
		if ((ret = v4l2loopback_lookup(device_nr, &dev)) < 0)
			break;
		MARK();
		
		if ((device_nr != conf.capture_nr) && (conf.capture_nr >= 0) && (ret != v4l2loopback_lookup(conf.capture_nr, 0)))
			break;
		MARK();
		
		if ((device_nr != conf.output_nr) && (conf.output_nr >= 0) && (ret != v4l2loopback_lookup(conf.output_nr, 0)))
			break;
		MARK();

		
		snprintf(conf.card_label, sizeof(conf.card_label), "%s", dev->card_label);
		MARK();
		conf.output_nr = conf.capture_nr = dev->vdev->num;
		conf.max_width = dev->max_width;
		conf.max_height = dev->max_height;
		conf.announce_all_caps = dev->announce_all_caps;
		conf.max_buffers = dev->buffers_number;
		conf.max_openers = dev->max_openers;
		conf.debug = debug;
		MARK();
		if (copy_to_user((void *)parm, &conf, sizeof(conf))) {
			ret = -EFAULT;
			break;
		}
		MARK();
		ret = 0;
		;
		break;
	}

	MARK();
	mutex_unlock(&v4l2loopback_ctl_mutex);
	MARK();
	return ret;
}



static const struct file_operations v4l2loopback_ctl_fops = {
	
	.owner		= THIS_MODULE, .open		= nonseekable_open, .unlocked_ioctl	= v4l2loopback_control_ioctl, .compat_ioctl	= v4l2loopback_control_ioctl, .llseek		= noop_llseek,  };






static struct miscdevice v4l2loopback_misc = {
	
	.minor		= MISC_DYNAMIC_MINOR, .name		= "v4l2loopback", .fops		= &v4l2loopback_ctl_fops,  };




static const struct v4l2_file_operations v4l2_loopback_fops = {
	
	.owner		= THIS_MODULE, .open		= v4l2_loopback_open, .release	= v4l2_loopback_close, .read		= v4l2_loopback_read, .write		= v4l2_loopback_write, .poll		= v4l2_loopback_poll, .mmap		= v4l2_loopback_mmap, .unlocked_ioctl	= video_ioctl2,  };









static const struct v4l2_ioctl_ops v4l2_loopback_ioctl_ops = {
	
	.vidioc_querycap		= &vidioc_querycap,  .vidioc_enum_framesizes		= &vidioc_enum_framesizes, .vidioc_enum_frameintervals	= &vidioc_enum_frameintervals,    .vidioc_queryctrl		= &vidioc_queryctrl, .vidioc_g_ctrl			= &vidioc_g_ctrl, .vidioc_s_ctrl			= &vidioc_s_ctrl,   .vidioc_enum_output		= &vidioc_enum_output, .vidioc_g_output		= &vidioc_g_output, .vidioc_s_output		= &vidioc_s_output,  .vidioc_enum_input		= &vidioc_enum_input, .vidioc_g_input			= &vidioc_g_input, .vidioc_s_input			= &vidioc_s_input,  .vidioc_enum_fmt_vid_cap	= &vidioc_enum_fmt_cap, .vidioc_g_fmt_vid_cap		= &vidioc_g_fmt_cap, .vidioc_s_fmt_vid_cap		= &vidioc_s_fmt_cap, .vidioc_try_fmt_vid_cap		= &vidioc_try_fmt_cap,  .vidioc_enum_fmt_vid_out	= &vidioc_enum_fmt_out, .vidioc_s_fmt_vid_out		= &vidioc_s_fmt_out, .vidioc_g_fmt_vid_out		= &vidioc_g_fmt_out, .vidioc_try_fmt_vid_out		= &vidioc_try_fmt_out,   .vidioc_s_fmt_vid_overlay	= &vidioc_s_fmt_overlay, .vidioc_g_fmt_vid_overlay	= &vidioc_g_fmt_overlay,    .vidioc_s_std			= &vidioc_s_std, .vidioc_g_std			= &vidioc_g_std, .vidioc_querystd		= &vidioc_querystd,   .vidioc_g_parm			= &vidioc_g_parm, .vidioc_s_parm			= &vidioc_s_parm,  .vidioc_reqbufs			= &vidioc_reqbufs, .vidioc_querybuf		= &vidioc_querybuf, .vidioc_qbuf			= &vidioc_qbuf, .vidioc_dqbuf			= &vidioc_dqbuf,  .vidioc_streamon		= &vidioc_streamon, .vidioc_streamoff		= &vidioc_streamoff,   .vidiocgmbuf			= &vidiocgmbuf,   .vidioc_subscribe_event		= &vidioc_subscribe_event, .vidioc_unsubscribe_event	= &v4l2_event_unsubscribe,  };



























































static int free_device_cb(int id, void *ptr, void *data)
{
	struct v4l2_loopback_device *dev = ptr;
	v4l2_loopback_remove(dev);
	return 0;
}
static void free_devices(void)
{
	idr_for_each(&v4l2loopback_index_idr, &free_device_cb, NULL);
	idr_destroy(&v4l2loopback_index_idr);
}

static int __init v4l2loopback_init_module(void)
{
	int err;
	int i;
	MARK();

	err = misc_register(&v4l2loopback_misc);
	if (err < 0)
		return err;

	if (devices < 0) {
		devices = 1;

		
		for (i = MAX_DEVICES - 1; i >= 0; i--) {
			if (video_nr[i] >= 0) {
				devices = i + 1;
				break;
			}
		}
	}

	if (devices > MAX_DEVICES) {
		devices = MAX_DEVICES;
		printk(KERN_INFO "v4l2loopback: number of initial devices is limited to: %d\n", MAX_DEVICES);

	}

	if (max_buffers > MAX_BUFFERS) {
		max_buffers = MAX_BUFFERS;
		printk(KERN_INFO "v4l2loopback: number of buffers is limited to: %d\n", MAX_BUFFERS);

	}

	if (max_openers < 0) {
		printk(KERN_INFO "v4l2loopback: allowing %d openers rather than %d\n", 2, max_openers);

		max_openers = 2;
	}

	if (max_width < V4L2LOOPBACK_SIZE_MIN_WIDTH) {
		max_width = V4L2LOOPBACK_SIZE_DEFAULT_MAX_WIDTH;
		printk(KERN_INFO "v4l2loopback: using max_width %d\n", max_width);
	}
	if (max_height < V4L2LOOPBACK_SIZE_MIN_HEIGHT) {
		max_height = V4L2LOOPBACK_SIZE_DEFAULT_MAX_HEIGHT;
		printk(KERN_INFO "v4l2loopback: using max_height %d\n", max_height);
	}

	
	for (i = 0; i < devices; i++) {
		struct v4l2_loopback_config cfg = {
			
			.output_nr		= video_nr[i], .capture_nr		= video_nr[i], .max_width		= max_width, .max_height		= max_height, .announce_all_caps	= (!exclusive_caps[i]), .max_buffers		= max_buffers, .max_openers		= max_openers, .debug			= debug,  };








		cfg.card_label[0] = 0;
		if (card_label[i])
			snprintf(cfg.card_label, sizeof(cfg.card_label), "%s", card_label[i]);
		err = v4l2_loopback_add(&cfg, 0);
		if (err) {
			free_devices();
			goto error;
		}
	}

	dprintk("module installed\n");

	printk(KERN_INFO "v4l2loopback driver version %d.%d.%d%s loaded\n",  (V4L2LOOPBACK_VERSION_CODE >> 16) & 0xff, (V4L2LOOPBACK_VERSION_CODE >>  8) & 0xff, (V4L2LOOPBACK_VERSION_CODE      ) & 0xff,  " (" STRINGIFY2(SNAPSHOT_VERSION) ")"  ""  );









	

	return 0;
error:
	misc_deregister(&v4l2loopback_misc);
	return err;
}


static void v4l2loopback_cleanup_module(void)
{
	MARK();
	
	free_devices();
	
	misc_deregister(&v4l2loopback_misc);
	dprintk("module removed\n");
}


MODULE_ALIAS_MISCDEV(MISC_DYNAMIC_MINOR);

module_init(v4l2loopback_init_module);
module_exit(v4l2loopback_cleanup_module);



static int vidioc_queryctrl(struct file *file, void *fh, struct v4l2_queryctrl *q) __attribute__((unused));
static int vidioc_g_ctrl(struct file *file, void *fh, struct v4l2_control *c)
	__attribute__((unused));
static int vidioc_s_ctrl(struct file *file, void *fh, struct v4l2_control *c)
	__attribute__((unused));

