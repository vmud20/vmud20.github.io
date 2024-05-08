




















static void query (void);
static void run   (const gchar      *name, gint              nparams, const GimpParam  *param, gint             *nreturn_vals, GimpParam       **return_vals);




static gint      load_palette   (const gchar  *file, FILE         *fp, guchar        palette[], GError      **error);


static gint32    load_image     (const gchar  *file, const gchar  *brief, GError      **error);

static gboolean  save_image     (const gchar  *file, const gchar  *brief, gint32        image, gint32        layer, GError      **error);



static void      palette_dialog (const gchar  *title);
static gboolean  need_palette   (const gchar  *file, GError      **error);




const GimpPlugInInfo  PLUG_IN_INFO = {
  NULL,   NULL, query, run, };




static gchar *palette_file = NULL;
static gsize  data_length  = 0;



MAIN ()



static void query (void)
{
  static const GimpParamDef load_args[] = {
    { GIMP_PDB_INT32,  "run-mode",         "The run mode { RUN-INTERACTIVE (0), RUN-NONINTERACTIVE (1) }"  }, { GIMP_PDB_STRING, "filename",         "Filename to load image from"   }, { GIMP_PDB_STRING, "raw-filename",     "Name entered"                  }, { GIMP_PDB_STRING, "palette-filename", "Filename to load palette from" }


  };
  static const GimpParamDef load_return_vals[] = {
    { GIMP_PDB_IMAGE, "image", "Output image" }
  };

  static const GimpParamDef save_args[] = {
    { GIMP_PDB_INT32,    "run-mode",         "The run mode { RUN-INTERACTIVE (0), RUN-NONINTERACTIVE (1) }" }, { GIMP_PDB_IMAGE,    "image",            "Input image"                  }, { GIMP_PDB_DRAWABLE, "drawable",         "Drawable to save"             }, { GIMP_PDB_STRING,   "filename",         "Filename to save image to"    }, { GIMP_PDB_STRING,   "raw-filename",     "Name entered"                 }, { GIMP_PDB_STRING,   "palette-filename", "Filename to save palette to"  }, };






  gimp_install_procedure (LOAD_PROC, "Loads files in KISS CEL file format", "This plug-in loads individual KISS cell files.", "Nick Lamb", "Nick Lamb <njl195@zepler.org.uk>", "May 1998", N_("KISS CEL"), NULL, GIMP_PLUGIN, G_N_ELEMENTS (load_args), G_N_ELEMENTS (load_return_vals), load_args, load_return_vals);











  gimp_register_magic_load_handler (LOAD_PROC, "cel", "", "0,string,KiSS\\040");



  gimp_install_procedure (SAVE_PROC, "Saves files in KISS CEL file format", "This plug-in saves individual KISS cell files.", "Nick Lamb", "Nick Lamb <njl195@zepler.org.uk>", "May 1998", N_("KISS CEL"), "RGB*, INDEXED*", GIMP_PLUGIN, G_N_ELEMENTS (save_args), 0, save_args, NULL);










  gimp_register_save_handler (SAVE_PROC, "cel", "");
}

static void run (const gchar      *name, gint              nparams, const GimpParam  *param, gint             *nreturn_vals, GimpParam       **return_vals)




{
  static GimpParam   values[2]; 
  GimpRunMode        run_mode;
  gint32             image_ID;
  gint32             drawable_ID;
  GimpPDBStatusType  status = GIMP_PDB_SUCCESS;
  gint32             image;
  GimpExportReturn   export = GIMP_EXPORT_CANCEL;
  GError            *error  = NULL;
  gint               needs_palette = 0;

  run_mode = param[0].data.d_int32;

  INIT_I18N ();

  

  *nreturn_vals = 1;
  *return_vals  = values;
  values[0].type          = GIMP_PDB_STATUS;
  values[0].data.d_status = GIMP_PDB_EXECUTION_ERROR;

  if (strcmp (name, LOAD_PROC) == 0)
    {
      if (run_mode != GIMP_RUN_NONINTERACTIVE)
        {
          data_length = gimp_get_data_size (SAVE_PROC);
          if (data_length > 0)
            {
              palette_file = g_malloc (data_length);
              gimp_get_data (SAVE_PROC, palette_file);
            }
          else {
              palette_file = g_strdup ("*.kcf");
              data_length = strlen (palette_file) + 1;
            }
        }

      if (run_mode == GIMP_RUN_NONINTERACTIVE)
        {
          palette_file = param[3].data.d_string;
          data_length = strlen (palette_file) + 1;
        }
      else if (run_mode == GIMP_RUN_INTERACTIVE)
        {
          
          needs_palette = need_palette (param[1].data.d_string, &error);

          if (! error)
            {
              if (needs_palette)
                palette_dialog (_("Load KISS Palette"));

              gimp_set_data (SAVE_PROC, palette_file, data_length);
            }
        }

      if (! error)
        {
          image = load_image (param[1].data.d_string, param[2].data.d_string, &error);

          if (image != -1)
            {
              *nreturn_vals = 2;
              values[1].type         = GIMP_PDB_IMAGE;
              values[1].data.d_image = image;
            }
          else {
              status = GIMP_PDB_EXECUTION_ERROR;
            }
        }
      else {
          status = GIMP_PDB_EXECUTION_ERROR;
        }
    }
  else if (strcmp (name, SAVE_PROC) == 0)
    {
      image_ID      = param[1].data.d_int32;
      drawable_ID   = param[2].data.d_int32;

      
      switch (run_mode)
        {
        case GIMP_RUN_INTERACTIVE:
        case GIMP_RUN_WITH_LAST_VALS:
          gimp_ui_init (PLUG_IN_BINARY, FALSE);
          export = gimp_export_image (&image_ID, &drawable_ID, NULL, (GIMP_EXPORT_CAN_HANDLE_RGB | GIMP_EXPORT_CAN_HANDLE_ALPHA | GIMP_EXPORT_CAN_HANDLE_INDEXED ));



          if (export == GIMP_EXPORT_CANCEL)
            {
              values[0].data.d_status = GIMP_PDB_CANCEL;
              return;
            }
          break;
        default:
          break;
        }

      if (save_image (param[3].data.d_string, param[4].data.d_string, image_ID, drawable_ID, &error))
        {
          gimp_set_data (SAVE_PROC, palette_file, data_length);
        }
      else {
          status = GIMP_PDB_EXECUTION_ERROR;
        }

      if (export == GIMP_EXPORT_EXPORT)
        gimp_image_delete (image_ID);
    }
  else {
      status = GIMP_PDB_CALLING_ERROR;
    }

  if (status != GIMP_PDB_SUCCESS && error)
    {
      *nreturn_vals = 2;
      values[1].type          = GIMP_PDB_STRING;
      values[1].data.d_string = error->message;
    }

  values[0].data.d_status = status;
}


static gboolean need_palette (const gchar *file, GError     **error)

{
  FILE   *fp;
  guchar  header[32];
  size_t  n_read;

  fp = g_fopen (file, "rb");
  if (fp == NULL)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), _("Could not open '%s' for reading: %s"), gimp_filename_to_utf8 (file), g_strerror (errno));

      return FALSE;
    }

  n_read = fread (header, 32, 1, fp);

  fclose (fp);

  if (n_read < 1)
    {
      g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED, _("EOF or error while reading image header"));
      return FALSE;
    }

  return (header[5] < 32);
}



static gint32 load_image (const gchar  *file, const gchar  *brief, GError      **error)


{
  FILE      *fp;            
  guchar     header[32];    
  gint       height, width,  offx, offy, colours, bpp;



  gint32     image,          layer;
  guchar    *palette,        *buffer, *line;

  GimpDrawable *drawable;   
  GimpPixelRgn  pixel_rgn;  

  gint       i, j, k;       
  size_t     n_read;        


  
  fp = g_fopen (file, "r");

  if (fp == NULL)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), _("Could not open '%s' for reading: %s"), gimp_filename_to_utf8 (file), g_strerror (errno));

      return -1;
    }

  gimp_progress_init_printf (_("Opening '%s'"), gimp_filename_to_utf8 (brief));

  

  n_read = fread (header, 4, 1, fp);

  if (n_read < 1)
    {
      g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED, _("EOF or error while reading image header"));
      return -1;
    }

  if (strncmp ((const gchar *) header, "KiSS", 4))
    {
      colours= 16;
      bpp = 4;
      width = header[0] + (256 * header[1]);
      height = header[2] + (256 * header[3]);
      offx= 0;
      offy= 0;
    }
  else {
      n_read = fread (header, 28, 1, fp);

      if (n_read < 1)
        {
          g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED, _("EOF or error while reading image header"));
          return -1;
        }

      bpp = header[1];
      if (bpp == 24)
        colours = -1;
      else colours = (1 << header[1]);
      width = header[4] + (256 * header[5]);
      height = header[6] + (256 * header[7]);
      offx = header[8] + (256 * header[9]);
      offy = header[10] + (256 * header[11]);
    }

  if (bpp == 32)
    image = gimp_image_new (width + offx, height + offy, GIMP_RGB);
  else image = gimp_image_new (width + offx, height + offy, GIMP_INDEXED);

  if (image == -1)
    {
      g_message (_("Can't create a new image"));
      fclose (fp);
      return -1;
    }

  gimp_image_set_filename (image, file);

  
  if (bpp == 32)
    layer = gimp_layer_new (image, _("Background"), width, height, GIMP_RGBA_IMAGE, 100, GIMP_NORMAL_MODE);
  else layer = gimp_layer_new (image, _("Background"), width, height, GIMP_INDEXEDA_IMAGE, 100, GIMP_NORMAL_MODE);

  gimp_image_insert_layer (image, layer, -1, 0);
  gimp_layer_set_offsets (layer, offx, offy);

  

  drawable = gimp_drawable_get (layer);

  gimp_pixel_rgn_init (&pixel_rgn, drawable, 0, 0, drawable->width, drawable->height, TRUE, FALSE);

  
  buffer = g_new (guchar, width * 4);
  line   = g_new (guchar, (width + 1) * 4);

  for (i = 0; i < height && !feof(fp); ++i)
    {
      switch (bpp)
        {
        case 4:
          n_read = fread (buffer, (width+1)/2, 1, fp);

          if (n_read < 1)
            {
              g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED, _("EOF or error while reading image data"));
              return -1;
            }

          for (j = 0, k = 0; j < width*2; j+= 4, ++k)
            {
              if (buffer[k] / 16 == 0)
                {
                  line[j]= 16;
                  line[j+1]= 0;
                }
              else {
                  line[j]= (buffer[k] / 16) - 1;
                  line[j+1]= 255;
                }
              if (buffer[k] % 16 == 0)
                {
                  line[j+2]= 16;
                  line[j+3]= 0;
                }
              else {
                  line[j+2]= (buffer[k] % 16) - 1;
                  line[j+3]= 255;
                }
            }
          break;

        case 8:
          n_read = fread (buffer, width, 1, fp);

          if (n_read < 1)
            {
              g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED, _("EOF or error while reading image data"));
              return -1;
            }

          for (j = 0, k = 0; j < width*2; j+= 2, ++k)
            {
              if (buffer[k] == 0)
                {
                  line[j]= 255;
                  line[j+1]= 0;
                }
              else {
                  line[j]= buffer[k] - 1;
                  line[j+1]= 255;
                }
            }
          break;

        case 32:
          n_read = fread (line, width*4, 1, fp);

          if (n_read < 1)
            {
              g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED, _("EOF or error while reading image data"));
              return -1;
            }

          
          for (j= 0; j < width; j++)
            {
              guint8 tmp = line[j*4];
              line[j*4] = line[j*4+2];
              line[j*4+2] = tmp;
            }
          break;

        default:
          g_message (_("Unsupported bit depth (%d)!"), bpp);
          return -1;
        }

      gimp_pixel_rgn_set_rect (&pixel_rgn, line, 0, i, drawable->width, 1);
      gimp_progress_update ((float) i / (float) height);
    }
  gimp_progress_update (1.0);

  

  fclose (fp);
  g_free (buffer);
  g_free (line);

  if (bpp != 32)
    {
      
      palette = g_new (guchar, colours*3);

      
      if (palette_file == NULL)
        {
          fp = NULL;
        }
      else {
          fp = g_fopen (palette_file, "r");

          if (fp == NULL)
            {
              g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), _("Could not open '%s' for reading: %s"), gimp_filename_to_utf8 (palette_file), g_strerror (errno));


              return -1;
            }
        }

      if (fp != NULL)
        {
          colours = load_palette (palette_file, fp, palette, error);
          fclose (fp);
          if (colours < 0)
            return -1;
        }
      else {
          for (i= 0; i < colours; ++i)
            {
              palette[i*3] = palette[i*3+1] = palette[i*3+2]= i * 256 / colours;
            }
        }

      gimp_image_set_colormap (image, palette + 3, colours - 1);

      

      g_free (palette);
    }

  

  gimp_drawable_flush (drawable);
  gimp_drawable_detach (drawable);

  return image;
}

static gint load_palette (const gchar *file, FILE        *fp, guchar       palette[], GError     **error)



{
  guchar        header[32];     
  guchar        buffer[2];
  int           i, bpp, colours= 0;
  size_t        n_read;

  n_read = fread (header, 4, 1, fp);

  if (n_read < 1)
    {
      g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED, _("'%s': EOF or error while reading palette header"), gimp_filename_to_utf8 (file));

      return -1;
    }

  if (!strncmp ((const gchar *) header, "KiSS", 4))
    {
      n_read = fread (header+4, 28, 1, fp);

      if (n_read < 1)
        {
          g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED, _("'%s': EOF or error while reading palette header"), gimp_filename_to_utf8 (file));

          return -1;
        }

      bpp = header[5];
      colours = header[8] + header[9] * 256;
      if (bpp == 12)
        {
          for (i = 0; i < colours; ++i)
            {
              n_read = fread (buffer, 1, 2, fp);

              if (n_read < 2)
                {
                  g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED, _("'%s': EOF or error while reading " "palette data"), gimp_filename_to_utf8 (file));


                  return -1;
                }

              palette[i*3]= buffer[0] & 0xf0;
              palette[i*3+1]= (buffer[1] & 0x0f) * 16;
              palette[i*3+2]= (buffer[0] & 0x0f) * 16;
            }
        }
      else {
          n_read = fread (palette, colours, 3, fp);

          if (n_read < 3)
            {
              g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED, _("'%s': EOF or error while reading palette data"), gimp_filename_to_utf8 (file));

              return -1;
            }
        }
    }
  else {
      colours = 16;
      fseek (fp, 0, SEEK_SET);
      for (i= 0; i < colours; ++i)
        {
          n_read = fread (buffer, 1, 2, fp);

          if (n_read < 2)
            {
              g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED, _("'%s': EOF or error while reading palette data"), gimp_filename_to_utf8 (file));

              return -1;
            }

          palette[i*3] = buffer[0] & 0xf0;
          palette[i*3+1] = (buffer[1] & 0x0f) * 16;
          palette[i*3+2] = (buffer[0] & 0x0f) * 16;
        }
    }

  return colours;
}

static gboolean save_image (const gchar  *file, const gchar  *brief, gint32        image, gint32        layer, GError      **error)




{
  FILE          *fp;            
  guchar         header[32];    
  gint           bpp;           
  gint           colours, type; 
  gint           offx, offy;    

  guchar        *buffer;        
  guchar        *line;          
  GimpDrawable  *drawable;      
  GimpPixelRgn   pixel_rgn;     

  gint           i, j, k;       

  
  type = gimp_drawable_type (layer);
  if (type != GIMP_INDEXEDA_IMAGE)
    bpp = 32;
  else bpp = 4;

  
  gimp_drawable_offsets (layer, &offx, &offy);

  drawable = gimp_drawable_get (layer);

  
  fp = g_fopen (file, "w");

  if (fp == NULL)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), _("Could not open '%s' for writing: %s"), gimp_filename_to_utf8 (file), g_strerror (errno));

      return FALSE;
    }

  gimp_progress_init_printf (_("Saving '%s'"), gimp_filename_to_utf8 (brief));

  
  memset (header, 0, 32);
  strcpy ((gchar *) header, "KiSS");
  header[4]= 0x20;

  
  if (bpp < 32)
    {
      g_free (gimp_image_get_colormap (image, &colours));
      if (colours > 15)
        {
          header[5] = 8;
        }
      else {
          header[5] = 4;
        }
    }
  else header[5] = 32;

  
  header[8]  = drawable->width % 256;
  header[9]  = drawable->width / 256;
  header[10] = drawable->height % 256;
  header[11] = drawable->height / 256;
  header[12] = offx % 256;
  header[13] = offx / 256;
  header[14] = offy % 256;
  header[15] = offy / 256;
  fwrite (header, 32, 1, fp);

  
  gimp_pixel_rgn_init (&pixel_rgn, drawable, 0, 0, drawable->width, drawable->height, TRUE, FALSE);
  buffer = g_new (guchar, drawable->width*4);
  line = g_new (guchar, (drawable->width+1) * 4);

  
  for (i = 0; i < drawable->height; ++i)
    {
      gimp_pixel_rgn_get_rect (&pixel_rgn, line, 0, i, drawable->width, 1);
      memset (buffer, 0, drawable->width);

      if (bpp == 32)
        {
          for (j = 0; j < drawable->width; j++)
            {
              buffer[4*j] = line[4*j+2];     
              buffer[4*j+1] = line[4*j+1];   
              buffer[4*j+2] = line[4*j+0];   
              buffer[4*j+3] = line[4*j+3];   
            }
          fwrite (buffer, drawable->width, 4, fp);
        }
      else if (colours > 16)
        {
          for (j = 0, k = 0; j < drawable->width*2; j+= 2, ++k)
            {
              if (line[j+1] > 127)
                {
                  buffer[k]= line[j] + 1;
                }
            }
          fwrite (buffer, drawable->width, 1, fp);
        }
      else {
          for (j = 0, k = 0; j < drawable->width*2; j+= 4, ++k)
            {
              buffer[k] = 0;
              if (line[j+1] > 127)
                {
                  buffer[k] += (line[j] + 1)<< 4;
                }
              if (line[j+3] > 127)
                {
                  buffer[k] += (line[j+2] + 1);
                }
            }
          fwrite (buffer, (drawable->width+1)/2, 1, fp);
        }

      gimp_progress_update ((float) i / (float) drawable->height);
    }
  gimp_progress_update (1.0);

  
  fclose (fp);
  g_free (buffer);
  g_free (line);

  return TRUE;
}

static void palette_dialog (const gchar *title)
{
  GtkWidget *dialog;

  gimp_ui_init (PLUG_IN_BINARY, FALSE);

  dialog = gtk_file_chooser_dialog_new (title, NULL, GTK_FILE_CHOOSER_ACTION_OPEN,  GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_OPEN,   GTK_RESPONSE_OK,  NULL);






  gtk_dialog_set_alternative_button_order (GTK_DIALOG (dialog), GTK_RESPONSE_OK, GTK_RESPONSE_CANCEL, -1);



  gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (dialog), palette_file);

  gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);

  gtk_widget_show (dialog);

  if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_OK)
    {
      g_free (palette_file);
      palette_file = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
      data_length = strlen (palette_file) + 1;
    }

  gtk_widget_destroy (dialog);
}
