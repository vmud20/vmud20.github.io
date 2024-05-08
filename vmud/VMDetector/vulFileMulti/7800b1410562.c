













static const char kbd_descriptor[] = {
	0x05, 0x01,		 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01, 0x95, 0x08, 0x75, 0x01, 0x15, 0x00, 0x25, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x81, 0x02, 0x95, 0x05, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x05, 0x07, 0x19, 0x00, 0x2A, 0xFF, 0x00, 0x81, 0x00, 0xC0 };






























static const char mse_descriptor[] = {
	0x05, 0x01,		 0x09, 0x02, 0xA1, 0x01, 0x85, 0x02, 0x09, 0x01, 0xA1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x10, 0x15, 0x00, 0x25, 0x01, 0x95, 0x10, 0x75, 0x01, 0x81, 0x02, 0x05, 0x01, 0x16, 0x01, 0xF8, 0x26, 0xFF, 0x07, 0x75, 0x0C, 0x95, 0x02, 0x09, 0x30, 0x09, 0x31, 0x81, 0x06, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x01, 0x09, 0x38, 0x81, 0x06, 0x05, 0x0C, 0x0A, 0x38, 0x02, 0x95, 0x01, 0x81, 0x06, 0xC0, 0xC0, };



































static const char consumer_descriptor[] = {
	0x05, 0x0C,		 0x09, 0x01, 0xA1, 0x01, 0x85, 0x03, 0x75, 0x10, 0x95, 0x02, 0x15, 0x01, 0x26, 0x8C, 0x02, 0x19, 0x01, 0x2A, 0x8C, 0x02, 0x81, 0x00, 0xC0, };













static const char syscontrol_descriptor[] = {
	0x05, 0x01,		 0x09, 0x80, 0xA1, 0x01, 0x85, 0x04, 0x75, 0x02, 0x95, 0x01, 0x15, 0x01, 0x25, 0x03, 0x09, 0x82, 0x09, 0x81, 0x09, 0x83, 0x81, 0x60, 0x75, 0x06, 0x81, 0x03, 0xC0, };
















static const char media_descriptor[] = {
	0x06, 0xbc, 0xff,	 0x09, 0x88, 0xa1, 0x01, 0x85, 0x08, 0x19, 0x01, 0x29, 0xff, 0x15, 0x01, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00, 0xc0, };
























static const u8 hid_reportid_size_map[NUMBER_OF_HID_REPORTS] = {
	[1] = 8,		 [2] = 8, [3] = 5, [4] = 2, [8] = 2, };








static struct hid_ll_driver logi_dj_ll_driver;

static int logi_dj_output_hidraw_report(struct hid_device *hid, u8 * buf, size_t count, unsigned char report_type);

static int logi_dj_recv_query_paired_devices(struct dj_receiver_dev *djrcv_dev);

static void logi_dj_recv_destroy_djhid_device(struct dj_receiver_dev *djrcv_dev, struct dj_report *dj_report)
{
	
	struct dj_device *dj_dev;
	unsigned long flags;

	spin_lock_irqsave(&djrcv_dev->lock, flags);
	dj_dev = djrcv_dev->paired_dj_devices[dj_report->device_index];
	djrcv_dev->paired_dj_devices[dj_report->device_index] = NULL;
	spin_unlock_irqrestore(&djrcv_dev->lock, flags);

	if (dj_dev != NULL) {
		hid_destroy_device(dj_dev->hdev);
		kfree(dj_dev);
	} else {
		dev_err(&djrcv_dev->hdev->dev, "%s: can't destroy a NULL device\n", __func__);
	}
}

static void logi_dj_recv_add_djhid_device(struct dj_receiver_dev *djrcv_dev, struct dj_report *dj_report)
{
	
	struct hid_device *djrcv_hdev = djrcv_dev->hdev;
	struct usb_interface *intf = to_usb_interface(djrcv_hdev->dev.parent);
	struct usb_device *usbdev = interface_to_usbdev(intf);
	struct hid_device *dj_hiddev;
	struct dj_device *dj_dev;

	
	unsigned char tmpstr[3];

	if (dj_report->report_params[DEVICE_PAIRED_PARAM_SPFUNCTION] & SPFUNCTION_DEVICE_LIST_EMPTY) {
		dbg_hid("%s: device list is empty\n", __func__);
		djrcv_dev->querying_devices = false;
		return;
	}

	if ((dj_report->device_index < DJ_DEVICE_INDEX_MIN) || (dj_report->device_index > DJ_DEVICE_INDEX_MAX)) {
		dev_err(&djrcv_hdev->dev, "%s: invalid device index:%d\n", __func__, dj_report->device_index);
		return;
	}

	if (djrcv_dev->paired_dj_devices[dj_report->device_index]) {
		
		dbg_hid("%s: device is already known\n", __func__);
		return;
	}

	dj_hiddev = hid_allocate_device();
	if (IS_ERR(dj_hiddev)) {
		dev_err(&djrcv_hdev->dev, "%s: hid_allocate_device failed\n", __func__);
		return;
	}

	dj_hiddev->ll_driver = &logi_dj_ll_driver;
	dj_hiddev->hid_output_raw_report = logi_dj_output_hidraw_report;

	dj_hiddev->dev.parent = &djrcv_hdev->dev;
	dj_hiddev->bus = BUS_USB;
	dj_hiddev->vendor = le16_to_cpu(usbdev->descriptor.idVendor);
	dj_hiddev->product = le16_to_cpu(usbdev->descriptor.idProduct);
	snprintf(dj_hiddev->name, sizeof(dj_hiddev->name), "Logitech Unifying Device. Wireless PID:%02x%02x", dj_report->report_params[DEVICE_PAIRED_PARAM_EQUAD_ID_MSB], dj_report->report_params[DEVICE_PAIRED_PARAM_EQUAD_ID_LSB]);



	usb_make_path(usbdev, dj_hiddev->phys, sizeof(dj_hiddev->phys));
	snprintf(tmpstr, sizeof(tmpstr), ":%d", dj_report->device_index);
	strlcat(dj_hiddev->phys, tmpstr, sizeof(dj_hiddev->phys));

	dj_dev = kzalloc(sizeof(struct dj_device), GFP_KERNEL);

	if (!dj_dev) {
		dev_err(&djrcv_hdev->dev, "%s: failed allocating dj_device\n", __func__);
		goto dj_device_allocate_fail;
	}

	dj_dev->reports_supported = get_unaligned_le32( dj_report->report_params + DEVICE_PAIRED_RF_REPORT_TYPE);
	dj_dev->hdev = dj_hiddev;
	dj_dev->dj_receiver_dev = djrcv_dev;
	dj_dev->device_index = dj_report->device_index;
	dj_hiddev->driver_data = dj_dev;

	djrcv_dev->paired_dj_devices[dj_report->device_index] = dj_dev;

	if (hid_add_device(dj_hiddev)) {
		dev_err(&djrcv_hdev->dev, "%s: failed adding dj_device\n", __func__);
		goto hid_add_device_fail;
	}

	return;

hid_add_device_fail:
	djrcv_dev->paired_dj_devices[dj_report->device_index] = NULL;
	kfree(dj_dev);
dj_device_allocate_fail:
	hid_destroy_device(dj_hiddev);
}

static void delayedwork_callback(struct work_struct *work)
{
	struct dj_receiver_dev *djrcv_dev = container_of(work, struct dj_receiver_dev, work);

	struct dj_report dj_report;
	unsigned long flags;
	int count;
	int retval;

	dbg_hid("%s\n", __func__);

	spin_lock_irqsave(&djrcv_dev->lock, flags);

	count = kfifo_out(&djrcv_dev->notif_fifo, &dj_report, sizeof(struct dj_report));

	if (count != sizeof(struct dj_report)) {
		dev_err(&djrcv_dev->hdev->dev, "%s: workitem triggered without " "notifications available\n", __func__);
		spin_unlock_irqrestore(&djrcv_dev->lock, flags);
		return;
	}

	if (!kfifo_is_empty(&djrcv_dev->notif_fifo)) {
		if (schedule_work(&djrcv_dev->work) == 0) {
			dbg_hid("%s: did not schedule the work item, was " "already queued\n", __func__);
		}
	}

	spin_unlock_irqrestore(&djrcv_dev->lock, flags);

	switch (dj_report.report_type) {
	case REPORT_TYPE_NOTIF_DEVICE_PAIRED:
		logi_dj_recv_add_djhid_device(djrcv_dev, &dj_report);
		break;
	case REPORT_TYPE_NOTIF_DEVICE_UNPAIRED:
		logi_dj_recv_destroy_djhid_device(djrcv_dev, &dj_report);
		break;
	default:
	
	if (!djrcv_dev->paired_dj_devices[dj_report.device_index]) {
		
		retval = logi_dj_recv_query_paired_devices(djrcv_dev);
		if (!retval) {
			
			break;
		}
		dev_err(&djrcv_dev->hdev->dev, "%s:logi_dj_recv_query_paired_devices " "error:%d\n", __func__, retval);

		}
		dbg_hid("%s: unexpected report type\n", __func__);
	}
}

static void logi_dj_recv_queue_notification(struct dj_receiver_dev *djrcv_dev, struct dj_report *dj_report)
{
	

	kfifo_in(&djrcv_dev->notif_fifo, dj_report, sizeof(struct dj_report));

	if (schedule_work(&djrcv_dev->work) == 0) {
		dbg_hid("%s: did not schedule the work item, was already " "queued\n", __func__);
	}
}

static void logi_dj_recv_forward_null_report(struct dj_receiver_dev *djrcv_dev, struct dj_report *dj_report)
{
	
	unsigned int i;
	u8 reportbuffer[MAX_REPORT_SIZE];
	struct dj_device *djdev;

	djdev = djrcv_dev->paired_dj_devices[dj_report->device_index];

	if (!djdev) {
		dbg_hid("djrcv_dev->paired_dj_devices[dj_report->device_index]" " is NULL, index %d\n", dj_report->device_index);
		kfifo_in(&djrcv_dev->notif_fifo, dj_report, sizeof(struct dj_report));

		if (schedule_work(&djrcv_dev->work) == 0) {
			dbg_hid("%s: did not schedule the work item, was already " "queued\n", __func__);
		}
		return;
	}

	memset(reportbuffer, 0, sizeof(reportbuffer));

	for (i = 0; i < NUMBER_OF_HID_REPORTS; i++) {
		if (djdev->reports_supported & (1 << i)) {
			reportbuffer[0] = i;
			if (hid_input_report(djdev->hdev, HID_INPUT_REPORT, reportbuffer, hid_reportid_size_map[i], 1)) {


				dbg_hid("hid_input_report error sending null " "report\n");
			}
		}
	}
}

static void logi_dj_recv_forward_report(struct dj_receiver_dev *djrcv_dev, struct dj_report *dj_report)
{
	
	struct dj_device *dj_device;

	dj_device = djrcv_dev->paired_dj_devices[dj_report->device_index];

	if (dj_device == NULL) {
		dbg_hid("djrcv_dev->paired_dj_devices[dj_report->device_index]" " is NULL, index %d\n", dj_report->device_index);
		kfifo_in(&djrcv_dev->notif_fifo, dj_report, sizeof(struct dj_report));

		if (schedule_work(&djrcv_dev->work) == 0) {
			dbg_hid("%s: did not schedule the work item, was already " "queued\n", __func__);
		}
		return;
	}

	if ((dj_report->report_type > ARRAY_SIZE(hid_reportid_size_map) - 1) || (hid_reportid_size_map[dj_report->report_type] == 0)) {
		dbg_hid("invalid report type:%x\n", dj_report->report_type);
		return;
	}

	if (hid_input_report(dj_device->hdev, HID_INPUT_REPORT, &dj_report->report_type, hid_reportid_size_map[dj_report->report_type], 1)) {

		dbg_hid("hid_input_report error\n");
	}
}


static int logi_dj_recv_send_report(struct dj_receiver_dev *djrcv_dev, struct dj_report *dj_report)
{
	struct hid_device *hdev = djrcv_dev->hdev;
	struct hid_report *report;
	struct hid_report_enum *output_report_enum;
	u8 *data = (u8 *)(&dj_report->device_index);
	int i;

	output_report_enum = &hdev->report_enum[HID_OUTPUT_REPORT];
	report = output_report_enum->report_id_hash[REPORT_ID_DJ_SHORT];

	if (!report) {
		dev_err(&hdev->dev, "%s: unable to find dj report\n", __func__);
		return -ENODEV;
	}

	for (i = 0; i < report->field[0]->report_count; i++)
		report->field[0]->value[i] = data[i];

	hid_hw_request(hdev, report, HID_REQ_SET_REPORT);

	return 0;
}

static int logi_dj_recv_query_paired_devices(struct dj_receiver_dev *djrcv_dev)
{
	struct dj_report *dj_report;
	int retval;

	
	if (djrcv_dev->querying_devices)
		return 0;

	dj_report = kzalloc(sizeof(struct dj_report), GFP_KERNEL);
	if (!dj_report)
		return -ENOMEM;
	dj_report->report_id = REPORT_ID_DJ_SHORT;
	dj_report->device_index = 0xFF;
	dj_report->report_type = REPORT_TYPE_CMD_GET_PAIRED_DEVICES;
	retval = logi_dj_recv_send_report(djrcv_dev, dj_report);
	kfree(dj_report);
	return retval;
}


static int logi_dj_recv_switch_to_dj_mode(struct dj_receiver_dev *djrcv_dev, unsigned timeout)
{
	struct dj_report *dj_report;
	int retval;

	dj_report = kzalloc(sizeof(struct dj_report), GFP_KERNEL);
	if (!dj_report)
		return -ENOMEM;
	dj_report->report_id = REPORT_ID_DJ_SHORT;
	dj_report->device_index = 0xFF;
	dj_report->report_type = REPORT_TYPE_CMD_SWITCH;
	dj_report->report_params[CMD_SWITCH_PARAM_DEVBITFIELD] = 0x3F;
	dj_report->report_params[CMD_SWITCH_PARAM_TIMEOUT_SECONDS] = (u8)timeout;
	retval = logi_dj_recv_send_report(djrcv_dev, dj_report);
	kfree(dj_report);
	return retval;
}


static int logi_dj_ll_open(struct hid_device *hid)
{
	dbg_hid("%s:%s\n", __func__, hid->phys);
	return 0;

}

static void logi_dj_ll_close(struct hid_device *hid)
{
	dbg_hid("%s:%s\n", __func__, hid->phys);
}

static int logi_dj_output_hidraw_report(struct hid_device *hid, u8 * buf, size_t count, unsigned char report_type)

{
	
	dbg_hid("%s\n", __func__);

	return 0;
}

static void rdcat(char **rdesc, unsigned int *rsize, const char *data, unsigned int size)
{
	memcpy(*rdesc + *rsize, data, size);
	*rsize += size;
}

static int logi_dj_ll_parse(struct hid_device *hid)
{
	struct dj_device *djdev = hid->driver_data;
	unsigned int rsize = 0;
	char *rdesc;
	int retval;

	dbg_hid("%s\n", __func__);

	djdev->hdev->version = 0x0111;
	djdev->hdev->country = 0x00;

	rdesc = kmalloc(MAX_RDESC_SIZE, GFP_KERNEL);
	if (!rdesc)
		return -ENOMEM;

	if (djdev->reports_supported & STD_KEYBOARD) {
		dbg_hid("%s: sending a kbd descriptor, reports_supported: %x\n", __func__, djdev->reports_supported);
		rdcat(&rdesc, &rsize, kbd_descriptor, sizeof(kbd_descriptor));
	}

	if (djdev->reports_supported & STD_MOUSE) {
		dbg_hid("%s: sending a mouse descriptor, reports_supported: " "%x\n", __func__, djdev->reports_supported);
		rdcat(&rdesc, &rsize, mse_descriptor, sizeof(mse_descriptor));
	}

	if (djdev->reports_supported & MULTIMEDIA) {
		dbg_hid("%s: sending a multimedia report descriptor: %x\n", __func__, djdev->reports_supported);
		rdcat(&rdesc, &rsize, consumer_descriptor, sizeof(consumer_descriptor));
	}

	if (djdev->reports_supported & POWER_KEYS) {
		dbg_hid("%s: sending a power keys report descriptor: %x\n", __func__, djdev->reports_supported);
		rdcat(&rdesc, &rsize, syscontrol_descriptor, sizeof(syscontrol_descriptor));
	}

	if (djdev->reports_supported & MEDIA_CENTER) {
		dbg_hid("%s: sending a media center report descriptor: %x\n", __func__, djdev->reports_supported);
		rdcat(&rdesc, &rsize, media_descriptor, sizeof(media_descriptor));
	}

	if (djdev->reports_supported & KBD_LEDS) {
		dbg_hid("%s: need to send kbd leds report descriptor: %x\n", __func__, djdev->reports_supported);
	}

	retval = hid_parse_report(hid, rdesc, rsize);
	kfree(rdesc);

	return retval;
}

static int logi_dj_ll_input_event(struct input_dev *dev, unsigned int type, unsigned int code, int value)
{
	
	struct hid_device *dj_hiddev = input_get_drvdata(dev);
	struct dj_device *dj_dev = dj_hiddev->driver_data;

	struct dj_receiver_dev *djrcv_dev = dev_get_drvdata(dj_hiddev->dev.parent);
	struct hid_device *dj_rcv_hiddev = djrcv_dev->hdev;
	struct hid_report_enum *output_report_enum;

	struct hid_field *field;
	struct hid_report *report;
	unsigned char *data;
	int offset;

	dbg_hid("%s: %s, type:%d | code:%d | value:%d\n", __func__, dev->phys, type, code, value);

	if (type != EV_LED)
		return -1;

	offset = hidinput_find_field(dj_hiddev, type, code, &field);

	if (offset == -1) {
		dev_warn(&dev->dev, "event field not found\n");
		return -1;
	}
	hid_set_field(field, offset, value);

	data = hid_alloc_report_buf(field->report, GFP_ATOMIC);
	if (!data) {
		dev_warn(&dev->dev, "failed to allocate report buf memory\n");
		return -1;
	}

	hid_output_report(field->report, &data[0]);

	output_report_enum = &dj_rcv_hiddev->report_enum[HID_OUTPUT_REPORT];
	report = output_report_enum->report_id_hash[REPORT_ID_DJ_SHORT];
	hid_set_field(report->field[0], 0, dj_dev->device_index);
	hid_set_field(report->field[0], 1, REPORT_TYPE_LEDS);
	hid_set_field(report->field[0], 2, data[1]);

	hid_hw_request(dj_rcv_hiddev, report, HID_REQ_SET_REPORT);

	kfree(data);

	return 0;
}

static int logi_dj_ll_start(struct hid_device *hid)
{
	dbg_hid("%s\n", __func__);
	return 0;
}

static void logi_dj_ll_stop(struct hid_device *hid)
{
	dbg_hid("%s\n", __func__);
}


static struct hid_ll_driver logi_dj_ll_driver = {
	.parse = logi_dj_ll_parse, .start = logi_dj_ll_start, .stop = logi_dj_ll_stop, .open = logi_dj_ll_open, .close = logi_dj_ll_close, .hidinput_input_event = logi_dj_ll_input_event, };







static int logi_dj_raw_event(struct hid_device *hdev, struct hid_report *report, u8 *data, int size)

{
	struct dj_receiver_dev *djrcv_dev = hid_get_drvdata(hdev);
	struct dj_report *dj_report = (struct dj_report *) data;
	unsigned long flags;
	bool report_processed = false;

	dbg_hid("%s, size:%d\n", __func__, size);

	

	spin_lock_irqsave(&djrcv_dev->lock, flags);
	if (dj_report->report_id == REPORT_ID_DJ_SHORT) {
		switch (dj_report->report_type) {
		case REPORT_TYPE_NOTIF_DEVICE_PAIRED:
		case REPORT_TYPE_NOTIF_DEVICE_UNPAIRED:
			logi_dj_recv_queue_notification(djrcv_dev, dj_report);
			break;
		case REPORT_TYPE_NOTIF_CONNECTION_STATUS:
			if (dj_report->report_params[CONNECTION_STATUS_PARAM_STATUS] == STATUS_LINKLOSS) {
				logi_dj_recv_forward_null_report(djrcv_dev, dj_report);
			}
			break;
		default:
			logi_dj_recv_forward_report(djrcv_dev, dj_report);
		}
		report_processed = true;
	}
	spin_unlock_irqrestore(&djrcv_dev->lock, flags);

	return report_processed;
}

static int logi_dj_probe(struct hid_device *hdev, const struct hid_device_id *id)
{
	struct usb_interface *intf = to_usb_interface(hdev->dev.parent);
	struct dj_receiver_dev *djrcv_dev;
	int retval;

	if (is_dj_device((struct dj_device *)hdev->driver_data))
		return -ENODEV;

	dbg_hid("%s called for ifnum %d\n", __func__, intf->cur_altsetting->desc.bInterfaceNumber);

	
	if (intf->cur_altsetting->desc.bInterfaceNumber != LOGITECH_DJ_INTERFACE_NUMBER) {
		dbg_hid("%s: ignoring ifnum %d\n", __func__, intf->cur_altsetting->desc.bInterfaceNumber);
		return -ENODEV;
	}

	

	djrcv_dev = kzalloc(sizeof(struct dj_receiver_dev), GFP_KERNEL);
	if (!djrcv_dev) {
		dev_err(&hdev->dev, "%s:failed allocating dj_receiver_dev\n", __func__);
		return -ENOMEM;
	}
	djrcv_dev->hdev = hdev;
	INIT_WORK(&djrcv_dev->work, delayedwork_callback);
	spin_lock_init(&djrcv_dev->lock);
	if (kfifo_alloc(&djrcv_dev->notif_fifo, DJ_MAX_NUMBER_NOTIFICATIONS * sizeof(struct dj_report), GFP_KERNEL)) {

		dev_err(&hdev->dev, "%s:failed allocating notif_fifo\n", __func__);
		kfree(djrcv_dev);
		return -ENOMEM;
	}
	hid_set_drvdata(hdev, djrcv_dev);

	
	retval = hid_parse(hdev);
	if (retval) {
		dev_err(&hdev->dev, "%s:parse of interface 2 failed\n", __func__);
		goto hid_parse_fail;
	}

	
	retval = hid_hw_start(hdev, HID_CONNECT_DEFAULT);
	if (retval) {
		dev_err(&hdev->dev, "%s:hid_hw_start returned error\n", __func__);
		goto hid_hw_start_fail;
	}

	retval = logi_dj_recv_switch_to_dj_mode(djrcv_dev, 0);
	if (retval < 0) {
		dev_err(&hdev->dev, "%s:logi_dj_recv_switch_to_dj_mode returned error:%d\n", __func__, retval);

		goto switch_to_dj_mode_fail;
	}

	
	retval = hid_hw_open(hdev);
	if (retval < 0) {
		dev_err(&hdev->dev, "%s:hid_hw_open returned error:%d\n", __func__, retval);
		goto llopen_failed;
	}

	
	hid_device_io_start(hdev);

	retval = logi_dj_recv_query_paired_devices(djrcv_dev);
	if (retval < 0) {
		dev_err(&hdev->dev, "%s:logi_dj_recv_query_paired_devices " "error:%d\n", __func__, retval);
		goto logi_dj_recv_query_paired_devices_failed;
	}

	return retval;

logi_dj_recv_query_paired_devices_failed:
	hid_hw_close(hdev);

llopen_failed:
switch_to_dj_mode_fail:
	hid_hw_stop(hdev);

hid_hw_start_fail:
hid_parse_fail:
	kfifo_free(&djrcv_dev->notif_fifo);
	kfree(djrcv_dev);
	hid_set_drvdata(hdev, NULL);
	return retval;

}


static int logi_dj_reset_resume(struct hid_device *hdev)
{
	int retval;
	struct dj_receiver_dev *djrcv_dev = hid_get_drvdata(hdev);

	retval = logi_dj_recv_switch_to_dj_mode(djrcv_dev, 0);
	if (retval < 0) {
		dev_err(&hdev->dev, "%s:logi_dj_recv_switch_to_dj_mode returned error:%d\n", __func__, retval);

	}

	return 0;
}


static void logi_dj_remove(struct hid_device *hdev)
{
	struct dj_receiver_dev *djrcv_dev = hid_get_drvdata(hdev);
	struct dj_device *dj_dev;
	int i;

	dbg_hid("%s\n", __func__);

	cancel_work_sync(&djrcv_dev->work);

	hid_hw_close(hdev);
	hid_hw_stop(hdev);

	
	for (i = 0; i < (DJ_MAX_PAIRED_DEVICES + DJ_DEVICE_INDEX_MIN); i++) {
		dj_dev = djrcv_dev->paired_dj_devices[i];
		if (dj_dev != NULL) {
			hid_destroy_device(dj_dev->hdev);
			kfree(dj_dev);
			djrcv_dev->paired_dj_devices[i] = NULL;
		}
	}

	kfifo_free(&djrcv_dev->notif_fifo);
	kfree(djrcv_dev);
	hid_set_drvdata(hdev, NULL);
}

static int logi_djdevice_probe(struct hid_device *hdev, const struct hid_device_id *id)
{
	int ret;
	struct dj_device *dj_dev = hdev->driver_data;

	if (!is_dj_device(dj_dev))
		return -ENODEV;

	ret = hid_parse(hdev);
	if (!ret)
		ret = hid_hw_start(hdev, HID_CONNECT_DEFAULT);

	return ret;
}

static const struct hid_device_id logi_dj_receivers[] = {
	{HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_UNIFYING_RECEIVER)}, {HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_UNIFYING_RECEIVER_2)}, {}



};

MODULE_DEVICE_TABLE(hid, logi_dj_receivers);

static struct hid_driver logi_djreceiver_driver = {
	.name = "logitech-djreceiver", .id_table = logi_dj_receivers, .probe = logi_dj_probe, .remove = logi_dj_remove, .raw_event = logi_dj_raw_event,  .reset_resume = logi_dj_reset_resume,  };









static const struct hid_device_id logi_dj_devices[] = {
	{HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_UNIFYING_RECEIVER)}, {HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_UNIFYING_RECEIVER_2)}, {}



};

static struct hid_driver logi_djdevice_driver = {
	.name = "logitech-djdevice", .id_table = logi_dj_devices, .probe = logi_djdevice_probe, };




static int __init logi_dj_init(void)
{
	int retval;

	dbg_hid("Logitech-DJ:%s\n", __func__);

	retval = hid_register_driver(&logi_djreceiver_driver);
	if (retval)
		return retval;

	retval = hid_register_driver(&logi_djdevice_driver);
	if (retval)
		hid_unregister_driver(&logi_djreceiver_driver);

	return retval;

}

static void __exit logi_dj_exit(void)
{
	dbg_hid("Logitech-DJ:%s\n", __func__);

	hid_unregister_driver(&logi_djdevice_driver);
	hid_unregister_driver(&logi_djreceiver_driver);

}

module_init(logi_dj_init);
module_exit(logi_dj_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Logitech");
MODULE_AUTHOR("Nestor Lopez Casado");
MODULE_AUTHOR("nlopezcasad@logitech.com");
