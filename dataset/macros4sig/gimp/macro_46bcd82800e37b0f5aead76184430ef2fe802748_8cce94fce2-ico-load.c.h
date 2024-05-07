
#include<stdlib.h>


#include<signal.h>

#include<errno.h>
#include<float.h>

#include<time.h>
#include<string.h>






#include<math.h>











#define INIT_I18N()	G_STMT_START{                                \
  bindtextdomain (GETTEXT_PACKAGE"-std-plug-ins",                    \
                  gimp_locale_directory ());                         \
  bind_textdomain_codeset (GETTEXT_PACKAGE"-std-plug-ins", "UTF-8"); \
  textdomain (GETTEXT_PACKAGE"-std-plug-ins");		             \
}G_STMT_END

#    define bind_textdomain_codeset(Domain, Codeset) (Domain)

#define D(x) \
{ \
  printf("ICO plugin: "); \
  printf x; \
}
#define ICO_ALPHA_THRESHOLD 127
#define ICO_MAXBUF          4096
#define ICO_PNG_MAGIC       0x474e5089
#define PLUG_IN_BINARY      "file-ico"
#define PLUG_IN_ROLE        "gimp-file-ico"



#define GIMP_IS_ZOOM_PREVIEW(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_ZOOM_PREVIEW))
#define GIMP_IS_ZOOM_PREVIEW_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_ZOOM_PREVIEW))
#define GIMP_TYPE_ZOOM_PREVIEW            (gimp_zoom_preview_get_type ())
#define GIMP_ZOOM_PREVIEW(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_ZOOM_PREVIEW, GimpZoomPreview))
#define GIMP_ZOOM_PREVIEW_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_ZOOM_PREVIEW, GimpZoomPreviewClass))
#define GIMP_ZOOM_PREVIEW_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_ZOOM_PREVIEW, GimpZoomPreviewClass))

#define GIMP_IS_SELECT_BUTTON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_SELECT_BUTTON))
#define GIMP_IS_SELECT_BUTTON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_SELECT_BUTTON))
#define GIMP_SELECT_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_SELECT_BUTTON, GimpSelectButton))
#define GIMP_SELECT_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_SELECT_BUTTON, GimpSelectButtonClass))
#define GIMP_SELECT_BUTTON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_SELECT_BUTTON, GimpSelectButtonClass))
#define GIMP_TYPE_SELECT_BUTTON            (gimp_select_button_get_type ())

#define GIMP_IS_PROGRESS_BAR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_PROGRESS_BAR))
#define GIMP_IS_PROGRESS_BAR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_PROGRESS_BAR))
#define GIMP_PROGRESS_BAR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_PROGRESS_BAR, GimpProgressBar))
#define GIMP_PROGRESS_BAR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_PROGRESS_BAR, GimpProgressBarClass))
#define GIMP_PROGRESS_BAR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_PROGRESS_BAR, GimpProgressBarClass))
#define GIMP_TYPE_PROGRESS_BAR            (gimp_progress_bar_get_type ())


#define GIMP_IS_PROC_BROWSER_DIALOG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_PROC_BROWSER_DIALOG))
#define GIMP_IS_PROC_BROWSER_DIALOG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_PROC_BROWSER_DIALOG))
#define GIMP_PROC_BROWSER_DIALOG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_PROC_BROWSER_DIALOG, GimpProcBrowserDialog))
#define GIMP_PROC_BROWSER_DIALOG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_PROC_BROWSER_DIALOG, GimpProcBrowserDialogClass))
#define GIMP_PROC_BROWSER_DIALOG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_PROC_BROWSER_DIALOG, GimpProcBrowserDialogClass))
#define GIMP_TYPE_PROC_BROWSER_DIALOG            (gimp_proc_browser_dialog_get_type ())

#define GIMP_IS_PATTERN_SELECT_BUTTON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_PATTERN_SELECT_BUTTON))
#define GIMP_IS_PATTERN_SELECT_BUTTON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_PATTERN_SELECT_BUTTON))
#define GIMP_PATTERN_SELECT_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_PATTERN_SELECT_BUTTON, GimpPatternSelectButton))
#define GIMP_PATTERN_SELECT_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_PATTERN_SELECT_BUTTON, GimpPatternSelectButtonClass))
#define GIMP_PATTERN_SELECT_BUTTON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_PATTERN_SELECT_BUTTON, GimpPatternSelectButtonClass))
#define GIMP_TYPE_PATTERN_SELECT_BUTTON            (gimp_pattern_select_button_get_type ())


#define GIMP_IS_PALETTE_SELECT_BUTTON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_PALETTE_SELECT_BUTTON))
#define GIMP_IS_PALETTE_SELECT_BUTTON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_PALETTE_SELECT_BUTTON))
#define GIMP_PALETTE_SELECT_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_PALETTE_SELECT_BUTTON, GimpPaletteSelectButton))
#define GIMP_PALETTE_SELECT_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_PALETTE_SELECT_BUTTON, GimpPaletteSelectButtonClass))
#define GIMP_PALETTE_SELECT_BUTTON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_PALETTE_SELECT_BUTTON, GimpPaletteSelectButtonClass))
#define GIMP_TYPE_PALETTE_SELECT_BUTTON            (gimp_palette_select_button_get_type ())



#define GIMP_CHANNEL_COMBO_BOX(obj)     (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_CHANNEL_COMBO_BOX, GimpChannelComboBox))
#define GIMP_DRAWABLE_COMBO_BOX(obj)    (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_DRAWABLE_COMBO_BOX, GimpDrawableComboBox))
#define GIMP_IS_CHANNEL_COMBO_BOX(obj)  (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_CHANNEL_COMBO_BOX))
#define GIMP_IS_DRAWABLE_COMBO_BOX(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_DRAWABLE_COMBO_BOX))
#define GIMP_IS_LAYER_COMBO_BOX(obj)    (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_LAYER_COMBO_BOX))
#define GIMP_IS_VECTORS_COMBO_BOX(obj)  (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_VECTORS_COMBO_BOX))
#define GIMP_LAYER_COMBO_BOX(obj)       (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_LAYER_COMBO_BOX, GimpLayerComboBox))
#define GIMP_TYPE_CHANNEL_COMBO_BOX     (gimp_channel_combo_box_get_type ())
#define GIMP_TYPE_DRAWABLE_COMBO_BOX    (gimp_drawable_combo_box_get_type ())
#define GIMP_TYPE_LAYER_COMBO_BOX       (gimp_layer_combo_box_get_type ())
#define GIMP_TYPE_VECTORS_COMBO_BOX     (gimp_vectors_combo_box_get_type ())
#define GIMP_VECTORS_COMBO_BOX(obj)     (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_VECTORS_COMBO_BOX, GimpVectorsComboBox))


#define GIMP_IMAGE_COMBO_BOX(obj)       (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_IMAGE_COMBO_BOX, GimpImageComboBox))
#define GIMP_IS_IMAGE_COMBO_BOX(obj)    (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_IMAGE_COMBO_BOX)
#define GIMP_TYPE_IMAGE_COMBO_BOX       (gimp_image_combo_box_get_type ())

#define GIMP_GRADIENT_SELECT_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_GRADIENT_SELECT_BUTTON, GimpGradientSelectButton))
#define GIMP_GRADIENT_SELECT_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_GRADIENT_SELECT_BUTTON, GimpGradientSelectButtonClass))
#define GIMP_GRADIENT_SELECT_BUTTON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_GRADIENT_SELECT_BUTTON, GimpGradientSelectButtonClass))
#define GIMP_IS_GRADIENT_SELECT_BUTTON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_GRADIENT_SELECT_BUTTON))
#define GIMP_IS_GRADIENT_SELECT_BUTTON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_GRADIENT_SELECT_BUTTON))
#define GIMP_TYPE_GRADIENT_SELECT_BUTTON            (gimp_gradient_select_button_get_type ())


#define GIMP_FONT_SELECT_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_FONT_SELECT_BUTTON, GimpFontSelectButton))
#define GIMP_FONT_SELECT_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_FONT_SELECT_BUTTON, GimpFontSelectButtonClass))
#define GIMP_FONT_SELECT_BUTTON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_FONT_SELECT_BUTTON, GimpFontSelectButtonClass))
#define GIMP_IS_FONT_SELECT_BUTTON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_FONT_SELECT_BUTTON))
#define GIMP_IS_FONT_SELECT_BUTTON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_FONT_SELECT_BUTTON))
#define GIMP_TYPE_FONT_SELECT_BUTTON            (gimp_font_select_button_get_type ())



#define GIMP_DRAWABLE_PREVIEW(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_DRAWABLE_PREVIEW, GimpDrawablePreview))
#define GIMP_DRAWABLE_PREVIEW_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_DRAWABLE_PREVIEW, GimpDrawablePreviewClass))
#define GIMP_DRAWABLE_PREVIEW_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_DRAWABLE_PREVIEW, GimpDrawablePreviewClass))
#define GIMP_IS_DRAWABLE_PREVIEW(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_DRAWABLE_PREVIEW))
#define GIMP_IS_DRAWABLE_PREVIEW_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_DRAWABLE_PREVIEW))
#define GIMP_TYPE_DRAWABLE_PREVIEW            (gimp_drawable_preview_get_type ())

#define GIMP_BRUSH_SELECT_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_BRUSH_SELECT_BUTTON, GimpBrushSelectButton))
#define GIMP_BRUSH_SELECT_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_BRUSH_SELECT_BUTTON, GimpBrushSelectButtonClass))
#define GIMP_BRUSH_SELECT_BUTTON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_BRUSH_SELECT_BUTTON, GimpBrushSelectButtonClass))
#define GIMP_IS_BRUSH_SELECT_BUTTON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_BRUSH_SELECT_BUTTON))
#define GIMP_IS_BRUSH_SELECT_BUTTON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_BRUSH_SELECT_BUTTON))
#define GIMP_TYPE_BRUSH_SELECT_BUTTON            (gimp_brush_select_button_get_type ())


#define GIMP_ASPECT_PREVIEW(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_ASPECT_PREVIEW, GimpAspectPreview))
#define GIMP_ASPECT_PREVIEW_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_ASPECT_PREVIEW, GimpAspectPreviewClass))
#define GIMP_ASPECT_PREVIEW_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_ASPECT_PREVIEW, GimpAspectPreviewClass))
#define GIMP_IS_ASPECT_PREVIEW(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_ASPECT_PREVIEW))
#define GIMP_IS_ASPECT_PREVIEW_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_ASPECT_PREVIEW))
#define GIMP_TYPE_ASPECT_PREVIEW            (gimp_aspect_preview_get_type ())



#define GIMP_TYPE_ASPECT_TYPE (gimp_aspect_type_get_type ())
#define GIMP_TYPE_CHAIN_POSITION (gimp_chain_position_get_type ())
#define GIMP_TYPE_COLOR_AREA_TYPE (gimp_color_area_type_get_type ())
#define GIMP_TYPE_COLOR_SELECTOR_CHANNEL (gimp_color_selector_channel_get_type ())
#define GIMP_TYPE_PAGE_SELECTOR_TARGET (gimp_page_selector_target_get_type ())
#define GIMP_TYPE_SIZE_ENTRY_UPDATE_POLICY (gimp_size_entry_update_policy_get_type ())
#define GIMP_TYPE_ZOOM_TYPE (gimp_zoom_type_get_type ())


#define GIMP_TYPE_COLOR_MANAGEMENT_MODE (gimp_color_management_mode_get_type ())
#define GIMP_TYPE_COLOR_RENDERING_INTENT (gimp_color_rendering_intent_get_type ())





#define GIMP_PARAM_READABLE       (G_PARAM_READABLE    | \
                                   GIMP_PARAM_STATIC_STRINGS)
#define GIMP_PARAM_READWRITE      (G_PARAM_READWRITE   | \
                                   GIMP_PARAM_STATIC_STRINGS)
#define GIMP_PARAM_STATIC_STRINGS (G_PARAM_STATIC_NAME | \
                                   G_PARAM_STATIC_NICK | \
                                   G_PARAM_STATIC_BLURB)
#define GIMP_PARAM_WRITABLE       (G_PARAM_WRITABLE    | \
                                   GIMP_PARAM_STATIC_STRINGS)

#define GIMP_TYPE_ADD_MASK_TYPE (gimp_add_mask_type_get_type ())
#define GIMP_TYPE_BLEND_MODE (gimp_blend_mode_get_type ())
#define GIMP_TYPE_BRUSH_GENERATED_SHAPE (gimp_brush_generated_shape_get_type ())
#define GIMP_TYPE_BUCKET_FILL_MODE (gimp_bucket_fill_mode_get_type ())
#define GIMP_TYPE_CAP_STYLE (gimp_cap_style_get_type ())
#define GIMP_TYPE_CHANNEL_OPS (gimp_channel_ops_get_type ())
#define GIMP_TYPE_CHANNEL_TYPE (gimp_channel_type_get_type ())
#define GIMP_TYPE_CHECK_SIZE (gimp_check_size_get_type ())
#define GIMP_TYPE_CHECK_TYPE (gimp_check_type_get_type ())
#define GIMP_TYPE_CLONE_TYPE (gimp_clone_type_get_type ())
#define GIMP_TYPE_COLOR_TAG (gimp_color_tag_get_type ())
#define GIMP_TYPE_COMPONENT_TYPE (gimp_component_type_get_type ())
#define GIMP_TYPE_CONVERT_PALETTE_TYPE (gimp_convert_palette_type_get_type ())
#define GIMP_TYPE_CONVOLVE_TYPE (gimp_convolve_type_get_type ())
#define GIMP_TYPE_DESATURATE_MODE (gimp_desaturate_mode_get_type ())
#define GIMP_TYPE_DODGE_BURN_TYPE (gimp_dodge_burn_type_get_type ())
#define GIMP_TYPE_FILL_TYPE (gimp_fill_type_get_type ())
#define GIMP_TYPE_FOREGROUND_EXTRACT_MODE (gimp_foreground_extract_mode_get_type ())
#define GIMP_TYPE_GRADIENT_SEGMENT_COLOR (gimp_gradient_segment_color_get_type ())
#define GIMP_TYPE_GRADIENT_SEGMENT_TYPE (gimp_gradient_segment_type_get_type ())
#define GIMP_TYPE_GRADIENT_TYPE (gimp_gradient_type_get_type ())
#define GIMP_TYPE_GRID_STYLE (gimp_grid_style_get_type ())
#define GIMP_TYPE_HUE_RANGE (gimp_hue_range_get_type ())
#define GIMP_TYPE_ICON_TYPE (gimp_icon_type_get_type ())
#define GIMP_TYPE_IMAGE_BASE_TYPE (gimp_image_base_type_get_type ())
#define GIMP_TYPE_IMAGE_TYPE (gimp_image_type_get_type ())
#define GIMP_TYPE_INK_BLOB_TYPE (gimp_ink_blob_type_get_type ())
#define GIMP_TYPE_INTERPOLATION_TYPE (gimp_interpolation_type_get_type ())
#define GIMP_TYPE_JOIN_STYLE (gimp_join_style_get_type ())
#define GIMP_TYPE_MASK_APPLY_MODE (gimp_mask_apply_mode_get_type ())
#define GIMP_TYPE_MERGE_TYPE (gimp_merge_type_get_type ())
#define GIMP_TYPE_MESSAGE_HANDLER_TYPE (gimp_message_handler_type_get_type ())
#define GIMP_TYPE_OFFSET_TYPE (gimp_offset_type_get_type ())
#define GIMP_TYPE_ORIENTATION_TYPE (gimp_orientation_type_get_type ())
#define GIMP_TYPE_PAINT_APPLICATION_MODE (gimp_paint_application_mode_get_type ())
#define GIMP_TYPE_PDB_ARG_TYPE (gimp_pdb_arg_type_get_type ())
#define GIMP_TYPE_PDB_ERROR_HANDLER (gimp_pdb_error_handler_get_type ())
#define GIMP_TYPE_PDB_PROC_TYPE (gimp_pdb_proc_type_get_type ())
#define GIMP_TYPE_PDB_STATUS_TYPE (gimp_pdb_status_type_get_type ())
#define GIMP_TYPE_PRECISION (gimp_precision_get_type ())
#define GIMP_TYPE_PROGRESS_COMMAND (gimp_progress_command_get_type ())
#define GIMP_TYPE_REPEAT_MODE (gimp_repeat_mode_get_type ())
#define GIMP_TYPE_ROTATION_TYPE (gimp_rotation_type_get_type ())
#define GIMP_TYPE_RUN_MODE (gimp_run_mode_get_type ())
#define GIMP_TYPE_SELECT_CRITERION (gimp_select_criterion_get_type ())
#define GIMP_TYPE_SIZE_TYPE (gimp_size_type_get_type ())
#define GIMP_TYPE_STACK_TRACE_MODE (gimp_stack_trace_mode_get_type ())
#define GIMP_TYPE_STROKE_METHOD (gimp_stroke_method_get_type ())
#define GIMP_TYPE_TEXT_DIRECTION (gimp_text_direction_get_type ())
#define GIMP_TYPE_TEXT_HINT_STYLE (gimp_text_hint_style_get_type ())
#define GIMP_TYPE_TEXT_JUSTIFICATION (gimp_text_justification_get_type ())
#define GIMP_TYPE_TRANSFER_MODE (gimp_transfer_mode_get_type ())
#define GIMP_TYPE_TRANSFORM_DIRECTION (gimp_transform_direction_get_type ())
#define GIMP_TYPE_TRANSFORM_RESIZE (gimp_transform_resize_get_type ())
#define GIMP_TYPE_USER_DIRECTORY (gimp_user_directory_get_type ())
#define GIMP_TYPE_VECTORS_STROKE_TYPE (gimp_vectors_stroke_type_get_type ())



#define GIMP_COORDINATES_CHAINBUTTON(sizeentry) \
        (g_object_get_data (G_OBJECT (sizeentry), "chainbutton"))
#define GIMP_RANDOM_SEED_SPINBUTTON(hbox) \
        (g_object_get_data (G_OBJECT (hbox), "spinbutton"))
#define GIMP_RANDOM_SEED_SPINBUTTON_ADJ(hbox)       \
        gtk_spin_button_get_adjustment \
        (GTK_SPIN_BUTTON (g_object_get_data (G_OBJECT (hbox), "spinbutton")))
#define GIMP_RANDOM_SEED_TOGGLE(hbox) \
        (g_object_get_data (G_OBJECT(hbox), "toggle"))




#define GIMP_IS_ZOOM_MODEL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_ZOOM_MODEL))
#define GIMP_IS_ZOOM_MODEL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_ZOOM_MODEL))
#define GIMP_TYPE_ZOOM_MODEL            (gimp_zoom_model_get_type ())
#define GIMP_ZOOM_MODEL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_ZOOM_MODEL, GimpZoomModel))
#define GIMP_ZOOM_MODEL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_ZOOM_MODEL, GimpZoomModelClass))
#define GIMP_ZOOM_MODEL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_ZOOM_MODEL, GimpZoomModel))


#define GIMP_WIDGETS_ERROR (gimp_widgets_error_quark ())

#define GIMP_IS_UNIT_STORE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_UNIT_STORE))
#define GIMP_IS_UNIT_STORE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_UNIT_STORE))
#define GIMP_TYPE_UNIT_STORE            (gimp_unit_store_get_type ())
#define GIMP_UNIT_STORE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_UNIT_STORE, GimpUnitStore))
#define GIMP_UNIT_STORE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_UNIT_STORE, GimpUnitStoreClass))
#define GIMP_UNIT_STORE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_UNIT_STORE, GimpUnitStoreClass))

#define GIMP_IS_UNIT_MENU(obj)         (G_TYPE_CHECK_INSTANCE_TYPE (obj, GIMP_TYPE_UNIT_MENU))
#define GIMP_IS_UNIT_MENU_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_UNIT_MENU))
#define GIMP_TYPE_UNIT_MENU            (gimp_unit_menu_get_type ())
#define GIMP_UNIT_MENU(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_UNIT_MENU, GimpUnitMenu))
#define GIMP_UNIT_MENU_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_UNIT_MENU, GimpUnitMenuClass))
#define GIMP_UNIT_MENU_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_UNIT_MENU, GimpUnitMenuClass))


#define GIMP_IS_UNIT_COMBO_BOX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_UNIT_COMBO_BOX))
#define GIMP_IS_UNIT_COMBO_BOX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_UNIT_COMBO_BOX))
#define GIMP_TYPE_UNIT_COMBO_BOX            (gimp_unit_combo_box_get_type ())
#define GIMP_UNIT_COMBO_BOX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_UNIT_COMBO_BOX, GimpUnitComboBox))
#define GIMP_UNIT_COMBO_BOX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_UNIT_COMBO_BOX, GimpUnitComboBoxClass))
#define GIMP_UNIT_COMBO_BOX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_UNIT_COMBO_BOX, GimpUnitComboBoxClass))

#define GIMP_IS_STRING_COMBO_BOX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_STRING_COMBO_BOX))
#define GIMP_IS_STRING_COMBO_BOX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_STRING_COMBO_BOX))
#define GIMP_STRING_COMBO_BOX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_STRING_COMBO_BOX, GimpStringComboBox))
#define GIMP_STRING_COMBO_BOX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_STRING_COMBO_BOX, GimpStringComboBoxClass))
#define GIMP_STRING_COMBO_BOX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_STRING_COMBO_BOX, GimpStringComboBoxClass))
#define GIMP_TYPE_STRING_COMBO_BOX            (gimp_string_combo_box_get_type ())

#define GIMP_IS_SIZE_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE (obj, GIMP_TYPE_SIZE_ENTRY))
#define GIMP_IS_SIZE_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_SIZE_ENTRY))
#define GIMP_SIZE_ENTRY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_SIZE_ENTRY, GimpSizeEntry))
#define GIMP_SIZE_ENTRY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_SIZE_ENTRY, GimpSizeEntryClass))
#define GIMP_SIZE_ENTRY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_SIZE_ENTRY, GimpSizeEntryClass))
#define GIMP_TYPE_SIZE_ENTRY            (gimp_size_entry_get_type ())

#define GIMP_IS_SCROLLED_PREVIEW(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_SCROLLED_PREVIEW))
#define GIMP_IS_SCROLLED_PREVIEW_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_SCROLLED_PREVIEW))
#define GIMP_SCROLLED_PREVIEW(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_SCROLLED_PREVIEW, GimpScrolledPreview))
#define GIMP_SCROLLED_PREVIEW_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_SCROLLED_PREVIEW, GimpScrolledPreviewClass))
#define GIMP_SCROLLED_PREVIEW_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_SCROLLED_PREVIEW, GimpScrolledPreviewClass))
#define GIMP_TYPE_SCROLLED_PREVIEW            (gimp_scrolled_preview_get_type ())

#define GIMP_SCALE_ENTRY_LABEL(adj) \
        (g_object_get_data (G_OBJECT (adj), "label"))
#define GIMP_SCALE_ENTRY_SCALE(adj) \
        (g_object_get_data (G_OBJECT (adj), "scale"))
#define GIMP_SCALE_ENTRY_SCALE_ADJ(adj)     \
        gtk_range_get_adjustment \
        (GTK_RANGE (g_object_get_data (G_OBJECT (adj), "scale")))
#define GIMP_SCALE_ENTRY_SPINBUTTON(adj) \
        (g_object_get_data (G_OBJECT (adj), "spinbutton"))
#define GIMP_SCALE_ENTRY_SPINBUTTON_ADJ(adj) \
        gtk_spin_button_get_adjustment \
        (GTK_SPIN_BUTTON (g_object_get_data (G_OBJECT (adj), "spinbutton")))

#define GIMP_IS_RULER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_RULER))
#define GIMP_IS_RULER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_RULER))
#define GIMP_RULER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_RULER, GimpRuler))
#define GIMP_RULER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_RULER, GimpRulerClass))
#define GIMP_RULER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_RULER, GimpRulerClass))
#define GIMP_TYPE_RULER            (gimp_ruler_get_type ())

#define GIMP_QUERY_BOX_VBOX(qbox) g_object_get_data (G_OBJECT (qbox), \
                                                     "gimp-query-box-vbox")


#define GIMP_IS_PREVIEW_AREA(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_PREVIEW_AREA))
#define GIMP_IS_PREVIEW_AREA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_PREVIEW_AREA))
#define GIMP_PREVIEW_AREA(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_PREVIEW_AREA, GimpPreviewArea))
#define GIMP_PREVIEW_AREA_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_PREVIEW_AREA, GimpPreviewAreaClass))
#define GIMP_PREVIEW_AREA_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_PREVIEW_AREA, GimpPreviewArea))
#define GIMP_TYPE_PREVIEW_AREA            (gimp_preview_area_get_type ())

#define GIMP_IS_PREVIEW(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_PREVIEW))
#define GIMP_IS_PREVIEW_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_PREVIEW))
#define GIMP_PREVIEW(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_PREVIEW, GimpPreview))
#define GIMP_PREVIEW_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_PREVIEW, GimpPreviewClass))
#define GIMP_PREVIEW_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_PREVIEW, GimpPreviewClass))
#define GIMP_TYPE_PREVIEW            (gimp_preview_get_type ())

#define GIMP_IS_PIXMAP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_PIXMAP))
#define GIMP_IS_PIXMAP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_PIXMAP))
#define GIMP_PIXMAP(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_PIXMAP, GimpPixmap))
#define GIMP_PIXMAP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_PIXMAP, GimpPixmapClass))
#define GIMP_PIXMAP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_PIXMAP, GimpPixmapClass))
#define GIMP_TYPE_PIXMAP            (gimp_pixmap_get_type ())

#define GIMP_IS_PICK_BUTTON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_PICK_BUTTON))
#define GIMP_IS_PICK_BUTTON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_PICK_BUTTON))
#define GIMP_PICK_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_PICK_BUTTON, GimpPickButton))
#define GIMP_PICK_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_PICK_BUTTON, GimpPickButtonClass))
#define GIMP_PICK_BUTTON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_PICK_BUTTON, GimpPickButtonClass))
#define GIMP_TYPE_PICK_BUTTON            (gimp_pick_button_get_type ())

#define GIMP_IS_PATH_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE (obj, GIMP_TYPE_PATH_EDITOR))
#define GIMP_IS_PATH_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_PATH_EDITOR))
#define GIMP_PATH_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_PATH_EDITOR, GimpPathEditor))
#define GIMP_PATH_EDITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_PATH_EDITOR, GimpPathEditorClass))
#define GIMP_PATH_EDITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_PATH_EDITOR, GimpPathEditorClass))
#define GIMP_TYPE_PATH_EDITOR            (gimp_path_editor_get_type ())

#define GIMP_IS_PAGE_SELECTOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_PAGE_SELECTOR))
#define GIMP_IS_PAGE_SELECTOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_PAGE_SELECTOR))
#define GIMP_PAGE_SELECTOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_PAGE_SELECTOR, GimpPageSelector))
#define GIMP_PAGE_SELECTOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_PAGE_SELECTOR, GimpPageSelectorClass))
#define GIMP_PAGE_SELECTOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_PAGE_SELECTOR, GimpPageSelectorClass))
#define GIMP_TYPE_PAGE_SELECTOR            (gimp_page_selector_get_type ())

#define GIMP_IS_OFFSET_AREA(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_OFFSET_AREA))
#define GIMP_IS_OFFSET_AREA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_OFFSET_AREA))
#define GIMP_OFFSET_AREA(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_OFFSET_AREA, GimpOffsetArea))
#define GIMP_OFFSET_AREA_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_OFFSET_AREA, GimpOffsetAreaClass))
#define GIMP_OFFSET_AREA_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_OFFSET_AREA, GimpOffsetAreaClass))
#define GIMP_TYPE_OFFSET_AREA            (gimp_offset_area_get_type ())

#define GIMP_IS_NUMBER_PAIR_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_NUMBER_PAIR_ENTRY))
#define GIMP_IS_NUMBER_PAIR_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_NUMBER_PAIR_ENTRY))
#define GIMP_NUMBER_PAIR_ENTRY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_NUMBER_PAIR_ENTRY, GimpNumberPairEntry))
#define GIMP_NUMBER_PAIR_ENTRY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_NUMBER_PAIR_ENTRY, GimpNumberPairEntryClass))
#define GIMP_NUMBER_PAIR_ENTRY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_NUMBER_PAIR_AREA, GimpNumberPairEntryClass))
#define GIMP_TYPE_NUMBER_PAIR_ENTRY            (gimp_number_pair_entry_get_type ())

#define GIMP_IS_MEMSIZE_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_MEMSIZE_ENTRY))
#define GIMP_IS_MEMSIZE_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_MEMSIZE_ENTRY))
#define GIMP_MEMSIZE_ENTRY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_MEMSIZE_ENTRY, GimpMemsizeEntry))
#define GIMP_MEMSIZE_ENTRY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_MEMSIZE_ENTRY, GimpMemsizeEntryClass))
#define GIMP_MEMSIZE_ENTRY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_MEMSIZE_ENTRY, GimpMemsizeEntryClass))
#define GIMP_TYPE_MEMSIZE_ENTRY            (gimp_memsize_entry_get_type ())

#define GIMP_INT_STORE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_INT_STORE, GimpIntStore))
#define GIMP_INT_STORE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_INT_STORE, GimpIntStoreClass))
#define GIMP_INT_STORE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_INT_STORE, GimpIntStoreClass))
#define GIMP_IS_INT_STORE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_INT_STORE))
#define GIMP_IS_INT_STORE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_INT_STORE))
#define GIMP_TYPE_INT_STORE            (gimp_int_store_get_type ())

#define GIMP_INT_COMBO_BOX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_INT_COMBO_BOX, GimpIntComboBox))
#define GIMP_INT_COMBO_BOX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_INT_COMBO_BOX, GimpIntComboBoxClass))
#define GIMP_INT_COMBO_BOX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_INT_COMBO_BOX, GimpIntComboBoxClass))
#define GIMP_IS_INT_COMBO_BOX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_INT_COMBO_BOX))
#define GIMP_IS_INT_COMBO_BOX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_INT_COMBO_BOX))
#define GIMP_TYPE_INT_COMBO_BOX            (gimp_int_combo_box_get_type ())

#define GIMP_STOCK_ANCHOR                   "gimp-anchor"
#define GIMP_STOCK_BRUSH                    GIMP_STOCK_TOOL_PAINTBRUSH
#define GIMP_STOCK_BUFFER                   "edit-paste"
#define GIMP_STOCK_CAP_BUTT                 "gimp-cap-butt"
#define GIMP_STOCK_CAP_ROUND                "gimp-cap-round"
#define GIMP_STOCK_CAP_SQUARE               "gimp-cap-square"
#define GIMP_STOCK_CENTER                   "gimp-center"
#define GIMP_STOCK_CHANNEL                  "gimp-channel"
#define GIMP_STOCK_CHANNELS                 "gimp-channels"
#define GIMP_STOCK_CHANNEL_ALPHA            "gimp-channel-alpha"
#define GIMP_STOCK_CHANNEL_BLUE             "gimp-channel-blue"
#define GIMP_STOCK_CHANNEL_GRAY             "gimp-channel-gray"
#define GIMP_STOCK_CHANNEL_GREEN            "gimp-channel-green"
#define GIMP_STOCK_CHANNEL_INDEXED          "gimp-channel-indexed"
#define GIMP_STOCK_CHANNEL_RED              "gimp-channel-red"
#define GIMP_STOCK_CHAR_PICKER              "gimp-char-picker"
#define GIMP_STOCK_CLIPBOARD                "gimp-clipboard"
#define GIMP_STOCK_CLOSE                    "gimp-close"
#define GIMP_STOCK_CLOSE_ALL                "gimp-close-all"
#define GIMP_STOCK_COLORMAP                 "gimp-colormap"
#define GIMP_STOCK_COLOR_CMYK               "gimp-color-cmyk"
#define GIMP_STOCK_COLOR_PICKER_BLACK       "gimp-color-picker-black"
#define GIMP_STOCK_COLOR_PICKER_GRAY        "gimp-color-picker-gray"
#define GIMP_STOCK_COLOR_PICKER_WHITE       "gimp-color-picker-white"
#define GIMP_STOCK_COLOR_PICK_FROM_SCREEN   "gimp-color-pick-from-screen"
#define GIMP_STOCK_COLOR_TRIANGLE           "gimp-color-triangle"
#define GIMP_STOCK_COLOR_WATER              "gimp-color-water"
#define GIMP_STOCK_CONTROLLER               "gimp-controller"
#define GIMP_STOCK_CONTROLLER_KEYBOARD      "gimp-controller-keyboard"
#define GIMP_STOCK_CONTROLLER_LINUX_INPUT   "gimp-controller-linux-input"
#define GIMP_STOCK_CONTROLLER_MIDI          "gimp-controller-midi"
#define GIMP_STOCK_CONTROLLER_MOUSE         GIMP_STOCK_CURSOR
#define GIMP_STOCK_CONTROLLER_WHEEL         "gimp-controller-wheel"
#define GIMP_STOCK_CONVERT_GRAYSCALE        "gimp-convert-grayscale"
#define GIMP_STOCK_CONVERT_INDEXED          "gimp-convert-indexed"
#define GIMP_STOCK_CONVERT_PRECISION        GIMP_STOCK_CONVERT_RGB
#define GIMP_STOCK_CONVERT_RGB              "gimp-convert-rgb"
#define GIMP_STOCK_CURSOR                   "gimp-cursor"
#define GIMP_STOCK_CURVE_FREE               "gimp-curve-free"
#define GIMP_STOCK_CURVE_SMOOTH             "gimp-curve-smooth"
#define GIMP_STOCK_DEFAULT_COLORS           "gimp-default-colors"
#define GIMP_STOCK_DETACH                   GTK_STOCK_CONVERT
#define GIMP_STOCK_DEVICE_STATUS            "gimp-device-status"
#define GIMP_STOCK_DISPLAY_FILTER           "gimp-display-filter"
#define GIMP_STOCK_DISPLAY_FILTER_COLORBLIND "gimp-display-filter-colorblind"
#define GIMP_STOCK_DISPLAY_FILTER_CONTRAST  "gimp-display-filter-contrast"
#define GIMP_STOCK_DISPLAY_FILTER_GAMMA     "gimp-display-filter-gamma"
#define GIMP_STOCK_DISPLAY_FILTER_LCMS      "gimp-display-filter-lcms"
#define GIMP_STOCK_DISPLAY_FILTER_PROOF     "gimp-display-filter-proof"
#define GIMP_STOCK_DUPLICATE                "gimp-duplicate"
#define GIMP_STOCK_DYNAMICS                 "gimp-dynamics"
#define GIMP_STOCK_EDIT                     "gtk-edit"
#define GIMP_STOCK_ERROR                    "gimp-error"
#define GIMP_STOCK_FILE_MANAGER             "gimp-file-manager"
#define GIMP_STOCK_FLIP_HORIZONTAL          "gimp-flip-horizontal"
#define GIMP_STOCK_FLIP_VERTICAL            "gimp-flip-vertical"
#define GIMP_STOCK_FLOATING_SELECTION       "gimp-floating-selection"
#define GIMP_STOCK_FRAME                    "gimp-frame"
#define GIMP_STOCK_GEGL                     "gimp-gegl"
#define GIMP_STOCK_GRADIENT                 GIMP_STOCK_TOOL_BLEND
#define GIMP_STOCK_GRADIENT_BILINEAR             "gimp-gradient-bilinear"
#define GIMP_STOCK_GRADIENT_CONICAL_ASYMMETRIC   "gimp-gradient-conical-asymmetric"
#define GIMP_STOCK_GRADIENT_CONICAL_SYMMETRIC    "gimp-gradient-conical-symmetric"
#define GIMP_STOCK_GRADIENT_LINEAR               "gimp-gradient-linear"
#define GIMP_STOCK_GRADIENT_RADIAL               "gimp-gradient-radial"
#define GIMP_STOCK_GRADIENT_SHAPEBURST_ANGULAR   "gimp-gradient-shapeburst-angular"
#define GIMP_STOCK_GRADIENT_SHAPEBURST_DIMPLED   "gimp-gradient-shapeburst-dimpled"
#define GIMP_STOCK_GRADIENT_SHAPEBURST_SPHERICAL "gimp-gradient-shapeburst-spherical"
#define GIMP_STOCK_GRADIENT_SPIRAL_ANTICLOCKWISE "gimp-gradient-spiral-anticlockwise"
#define GIMP_STOCK_GRADIENT_SPIRAL_CLOCKWISE     "gimp-gradient-spiral-clockwise"
#define GIMP_STOCK_GRADIENT_SQUARE               "gimp-gradient-square"
#define GIMP_STOCK_GRAVITY_EAST             "gimp-gravity-east"
#define GIMP_STOCK_GRAVITY_NORTH            "gimp-gravity-north"
#define GIMP_STOCK_GRAVITY_NORTH_EAST       "gimp-gravity-north-east"
#define GIMP_STOCK_GRAVITY_NORTH_WEST       "gimp-gravity-north-west"
#define GIMP_STOCK_GRAVITY_SOUTH            "gimp-gravity-south"
#define GIMP_STOCK_GRAVITY_SOUTH_EAST       "gimp-gravity-south-east"
#define GIMP_STOCK_GRAVITY_SOUTH_WEST       "gimp-gravity-south-west"
#define GIMP_STOCK_GRAVITY_WEST             "gimp-gravity-west"
#define GIMP_STOCK_GRID                     "gimp-grid"
#define GIMP_STOCK_HCENTER                  "gimp-hcenter"
#define GIMP_STOCK_HCHAIN                   "gimp-hchain"
#define GIMP_STOCK_HCHAIN_BROKEN            "gimp-hchain-broken"
#define GIMP_STOCK_HFILL                    "gimp-hfill"
#define GIMP_STOCK_HISTOGRAM                "gimp-histogram"
#define GIMP_STOCK_HISTOGRAM_LINEAR         "gimp-histogram-linear"
#define GIMP_STOCK_HISTOGRAM_LOGARITHMIC    "gimp-histogram-logarithmic"
#define GIMP_STOCK_IMAGE                    "gimp-image"
#define GIMP_STOCK_IMAGES                   "gimp-images"
#define GIMP_STOCK_IMAGE_OPEN               "gimp-image-open"
#define GIMP_STOCK_IMAGE_RELOAD             "gimp-image-reload"
#define GIMP_STOCK_INDEXED_PALETTE          "gimp-colormap"
#define GIMP_STOCK_INFO                     "gimp-info"
#define GIMP_STOCK_INPUT_DEVICE             "gimp-input-device"
#define GIMP_STOCK_INVERT                   "gimp-invert"
#define GIMP_STOCK_JOIN_BEVEL               "gimp-join-bevel"
#define GIMP_STOCK_JOIN_MITER               "gimp-join-miter"
#define GIMP_STOCK_JOIN_ROUND               "gimp-join-round"
#define GIMP_STOCK_LANDSCAPE                "gimp-landscape"
#define GIMP_STOCK_LAYER                    "gimp-layer"
#define GIMP_STOCK_LAYERS                   "gimp-layers"
#define GIMP_STOCK_LAYER_MASK               "gimp-layer-mask"
#define GIMP_STOCK_LAYER_TO_IMAGESIZE       "gimp-layer-to-imagesize"
#define GIMP_STOCK_LETTER_SPACING           "gimp-letter-spacing"
#define GIMP_STOCK_LINE_SPACING             "gimp-line-spacing"
#define GIMP_STOCK_LINKED                   "gimp-linked"
#define GIMP_STOCK_LIST                     "gimp-list"
#define GIMP_STOCK_MENU_LEFT                "gimp-menu-left"
#define GIMP_STOCK_MENU_RIGHT               "gimp-menu-right"
#define GIMP_STOCK_MERGE_DOWN               "gimp-merge-down"
#define GIMP_STOCK_MOVE_TO_SCREEN           "gimp-move-to-screen"
#define GIMP_STOCK_MYPAINT_BRUSH            GIMP_STOCK_TOOL_MYPAINT_BRUSH
#define GIMP_STOCK_NAVIGATION               "gimp-navigation"
#define GIMP_STOCK_PALETTE                  GTK_STOCK_SELECT_COLOR
#define GIMP_STOCK_PASTE_AS_NEW             "gimp-paste-as-new"
#define GIMP_STOCK_PASTE_INTO               "gimp-paste-into"
#define GIMP_STOCK_PATH                     "gimp-path"
#define GIMP_STOCK_PATHS                    "gimp-paths"
#define GIMP_STOCK_PATH_STROKE              "gimp-path-stroke"
#define GIMP_STOCK_PATTERN                  "gimp-pattern"
#define GIMP_STOCK_PLUGIN                   "gimp-plugin"
#define GIMP_STOCK_PORTRAIT                 "gimp-portrait"
#define GIMP_STOCK_PRINT_RESOLUTION         "document-print"
#define GIMP_STOCK_QMASK_OFF                "gimp-quick-mask-off"
#define GIMP_STOCK_QMASK_ON                 "gimp-quick-mask-on"
#define GIMP_STOCK_QUESTION                 "gimp-question"
#define GIMP_STOCK_QUICK_MASK_OFF           "gimp-quick-mask-off"
#define GIMP_STOCK_QUICK_MASK_ON            "gimp-quick-mask-on"
#define GIMP_STOCK_RESET                    "gimp-reset"
#define GIMP_STOCK_RESHOW_FILTER            "gimp-reshow-filter"
#define GIMP_STOCK_RESIZE                   "gimp-resize"
#define GIMP_STOCK_ROTATE_180               "gimp-rotate-180"
#define GIMP_STOCK_ROTATE_270               "gimp-rotate-270"
#define GIMP_STOCK_ROTATE_90                "gimp-rotate-90"
#define GIMP_STOCK_SAMPLE_POINT             "gimp-sample-point"
#define GIMP_STOCK_SCALE                    "gimp-scale"
#define GIMP_STOCK_SELECTION                "gimp-selection"
#define GIMP_STOCK_SELECTION_ADD            "gimp-selection-add"
#define GIMP_STOCK_SELECTION_ALL            "gimp-selection-all"
#define GIMP_STOCK_SELECTION_BORDER         "gimp-selection-border"
#define GIMP_STOCK_SELECTION_GROW           "gimp-selection-grow"
#define GIMP_STOCK_SELECTION_INTERSECT      "gimp-selection-intersect"
#define GIMP_STOCK_SELECTION_NONE           "gimp-selection-none"
#define GIMP_STOCK_SELECTION_REPLACE        "gimp-selection-replace"
#define GIMP_STOCK_SELECTION_SHRINK         "gimp-selection-shrink"
#define GIMP_STOCK_SELECTION_STROKE         "gimp-selection-stroke"
#define GIMP_STOCK_SELECTION_SUBTRACT       "gimp-selection-subtract"
#define GIMP_STOCK_SELECTION_TO_CHANNEL     "gimp-selection-to-channel"
#define GIMP_STOCK_SELECTION_TO_PATH        "gimp-selection-to-path"
#define GIMP_STOCK_SHAPE_CIRCLE             "gimp-shape-circle"
#define GIMP_STOCK_SHAPE_DIAMOND            "gimp-shape-diamond"
#define GIMP_STOCK_SHAPE_SQUARE             "gimp-shape-square"
#define GIMP_STOCK_SHRED                    "gimp-shred"
#define GIMP_STOCK_SWAP_COLORS              "gimp-swap-colors"
#define GIMP_STOCK_SYMMETRY                 "gimp-symmetry"
#define GIMP_STOCK_TEMPLATE                 "gimp-template"
#define GIMP_STOCK_TEXTURE                  "gimp-texture"
#define GIMP_STOCK_TEXT_DIR_LTR             "gimp-text-dir-ltr"
#define GIMP_STOCK_TEXT_DIR_RTL             "gimp-text-dir-rtl"
#define GIMP_STOCK_TEXT_LAYER               "gimp-text-layer"
#define GIMP_STOCK_TOOLS                    "gimp-tools"
#define GIMP_STOCK_TOOL_AIRBRUSH            "gimp-tool-airbrush"
#define GIMP_STOCK_TOOL_ALIGN               "gimp-tool-align"
#define GIMP_STOCK_TOOL_BLEND               "gimp-tool-blend"
#define GIMP_STOCK_TOOL_BLUR                "gimp-tool-blur"
#define GIMP_STOCK_TOOL_BRIGHTNESS_CONTRAST "gimp-tool-brightness-contrast"
#define GIMP_STOCK_TOOL_BUCKET_FILL         "gimp-tool-bucket-fill"
#define GIMP_STOCK_TOOL_BY_COLOR_SELECT     "gimp-tool-by-color-select"
#define GIMP_STOCK_TOOL_CAGE                "gimp-tool-cage"
#define GIMP_STOCK_TOOL_CLONE               "gimp-tool-clone"
#define GIMP_STOCK_TOOL_COLORIZE            "gimp-tool-colorize"
#define GIMP_STOCK_TOOL_COLOR_BALANCE       "gimp-tool-color-balance"
#define GIMP_STOCK_TOOL_COLOR_PICKER        "gimp-tool-color-picker"
#define GIMP_STOCK_TOOL_CROP                "gimp-tool-crop"
#define GIMP_STOCK_TOOL_CURVES              "gimp-tool-curves"
#define GIMP_STOCK_TOOL_DESATURATE          "gimp-tool-desaturate"
#define GIMP_STOCK_TOOL_DODGE               "gimp-tool-dodge"
#define GIMP_STOCK_TOOL_ELLIPSE_SELECT      "gimp-tool-ellipse-select"
#define GIMP_STOCK_TOOL_ERASER              "gimp-tool-eraser"
#define GIMP_STOCK_TOOL_FLIP                "gimp-tool-flip"
#define GIMP_STOCK_TOOL_FOREGROUND_SELECT   "gimp-tool-foreground-select"
#define GIMP_STOCK_TOOL_FREE_SELECT         "gimp-tool-free-select"
#define GIMP_STOCK_TOOL_FUZZY_SELECT        "gimp-tool-fuzzy-select"
#define GIMP_STOCK_TOOL_HANDLE_TRANSFORM    "gimp-tool-handle-transform"
#define GIMP_STOCK_TOOL_HEAL                "gimp-tool-heal"
#define GIMP_STOCK_TOOL_HUE_SATURATION      "gimp-tool-hue-saturation"
#define GIMP_STOCK_TOOL_INK                 "gimp-tool-ink"
#define GIMP_STOCK_TOOL_ISCISSORS           "gimp-tool-iscissors"
#define GIMP_STOCK_TOOL_LEVELS              "gimp-tool-levels"
#define GIMP_STOCK_TOOL_MEASURE             "gimp-tool-measure"
#define GIMP_STOCK_TOOL_MOVE                "gimp-tool-move"
#define GIMP_STOCK_TOOL_MYPAINT_BRUSH       "gimp-tool-mypaint-brush"
#define GIMP_STOCK_TOOL_N_POINT_DEFORMATION "gimp-tool-n-point-deformation"
#define GIMP_STOCK_TOOL_OPTIONS             "gimp-tool-options"
#define GIMP_STOCK_TOOL_PAINTBRUSH          "gimp-tool-paintbrush"
#define GIMP_STOCK_TOOL_PATH                "gimp-tool-path"
#define GIMP_STOCK_TOOL_PENCIL              "gimp-tool-pencil"
#define GIMP_STOCK_TOOL_PERSPECTIVE         "gimp-tool-perspective"
#define GIMP_STOCK_TOOL_PERSPECTIVE_CLONE   "gimp-tool-perspective-clone"
#define GIMP_STOCK_TOOL_POSTERIZE           "gimp-tool-posterize"
#define GIMP_STOCK_TOOL_PRESET              "gimp-tool-preset"
#define GIMP_STOCK_TOOL_RECT_SELECT         "gimp-tool-rect-select"
#define GIMP_STOCK_TOOL_ROTATE              "gimp-tool-rotate"
#define GIMP_STOCK_TOOL_SCALE               "gimp-tool-scale"
#define GIMP_STOCK_TOOL_SEAMLESS_CLONE      "gimp-tool-seamless-clone"
#define GIMP_STOCK_TOOL_SHEAR               "gimp-tool-shear"
#define GIMP_STOCK_TOOL_SMUDGE              "gimp-tool-smudge"
#define GIMP_STOCK_TOOL_TEXT                "gimp-tool-text"
#define GIMP_STOCK_TOOL_THRESHOLD           "gimp-tool-threshold"
#define GIMP_STOCK_TOOL_UNIFIED_TRANSFORM   "gimp-tool-unified-transform"
#define GIMP_STOCK_TOOL_WARP                "gimp-tool-warp"
#define GIMP_STOCK_TOOL_ZOOM                "gimp-tool-zoom"
#define GIMP_STOCK_TRANSPARENCY             "gimp-transparency"
#define GIMP_STOCK_UNDO_HISTORY             "gimp-undo-history"
#define GIMP_STOCK_USER_MANUAL              "gimp-user-manual"
#define GIMP_STOCK_VCENTER                  "gimp-vcenter"
#define GIMP_STOCK_VCHAIN                   "gimp-vchain"
#define GIMP_STOCK_VCHAIN_BROKEN            "gimp-vchain-broken"
#define GIMP_STOCK_VFILL                    "gimp-vfill"
#define GIMP_STOCK_VIDEO                    "gimp-video"
#define GIMP_STOCK_VISIBLE                  "gimp-visible"
#define GIMP_STOCK_WARNING                  "gimp-warning"
#define GIMP_STOCK_WEB                      "gimp-web"
#define GIMP_STOCK_WILBER                   "gimp-wilber"
#define GIMP_STOCK_WILBER_EEK               "gimp-wilber-eek"
#define GIMP_STOCK_ZOOM_FOLLOW_WINDOW       "gimp-zoom-follow-window"

#define GIMP_TYPE_HINT_BOX  (gimp_hint_box_get_type ())

#define GIMP_HELP_ID (gimp_help_id_quark ())

#define GIMP_FRAME(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_FRAME, GimpFrame))
#define GIMP_FRAME_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_FRAME, GimpFrameClass))
#define GIMP_FRAME_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_FRAME, GimpFrameClass))
#define GIMP_IS_FRAME(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_FRAME))
#define GIMP_IS_FRAME_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_FRAME))
#define GIMP_TYPE_FRAME            (gimp_frame_get_type ())

#define GIMP_FILE_ENTRY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_FILE_ENTRY, GimpFileEntry))
#define GIMP_FILE_ENTRY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_FILE_ENTRY, GimpFileEntryClass))
#define GIMP_FILE_ENTRY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_FILE_ENTRY, GimpFileEntryClass))
#define GIMP_IS_FILE_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE (obj, GIMP_TYPE_FILE_ENTRY))
#define GIMP_IS_FILE_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_FILE_ENTRY))
#define GIMP_TYPE_FILE_ENTRY            (gimp_file_entry_get_type ())


#define GIMP_ENUM_STORE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_ENUM_STORE, GimpEnumStore))
#define GIMP_ENUM_STORE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_ENUM_STORE, GimpEnumStoreClass))
#define GIMP_ENUM_STORE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_ENUM_STORE, GimpEnumStoreClass))
#define GIMP_IS_ENUM_STORE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_ENUM_STORE))
#define GIMP_IS_ENUM_STORE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_ENUM_STORE))
#define GIMP_TYPE_ENUM_STORE            (gimp_enum_store_get_type ())

#define GIMP_ENUM_LABEL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_ENUM_LABEL, GimpEnumLabel))
#define GIMP_ENUM_LABEL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_ENUM_LABEL, GimpEnumLabelClass))
#define GIMP_ENUM_LABEL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_ENUM_LABEL, GimpEnumLabelClass))
#define GIMP_IS_ENUM_LABEL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_ENUM_LABEL))
#define GIMP_IS_ENUM_LABEL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_ENUM_LABEL))
#define GIMP_TYPE_ENUM_LABEL            (gimp_enum_label_get_type ())

#define GIMP_ENUM_COMBO_BOX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_ENUM_COMBO_BOX, GimpEnumComboBox))
#define GIMP_ENUM_COMBO_BOX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_ENUM_COMBO_BOX, GimpEnumComboBoxClass))
#define GIMP_ENUM_COMBO_BOX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_ENUM_COMBO_BOX, GimpEnumComboBoxClass))
#define GIMP_IS_ENUM_COMBO_BOX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_ENUM_COMBO_BOX))
#define GIMP_IS_ENUM_COMBO_BOX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_ENUM_COMBO_BOX))
#define GIMP_TYPE_ENUM_COMBO_BOX            (gimp_enum_combo_box_get_type ())

#define GIMP_DIALOG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_DIALOG, GimpDialog))
#define GIMP_DIALOG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_DIALOG, GimpDialogClass))
#define GIMP_DIALOG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_DIALOG, GimpDialogClass))
#define GIMP_IS_DIALOG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_DIALOG))
#define GIMP_IS_DIALOG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_DIALOG))
#define GIMP_TYPE_DIALOG            (gimp_dialog_get_type ())

#define GIMP_COLOR_SELECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_SELECTION, GimpColorSelection))
#define GIMP_COLOR_SELECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_SELECTION, GimpColorSelectionClass))
#define GIMP_COLOR_SELECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_SELECTION, GimpColorSelectionClass))
#define GIMP_IS_COLOR_SELECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_SELECTION))
#define GIMP_IS_COLOR_SELECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_SELECTION))
#define GIMP_TYPE_COLOR_SELECTION            (gimp_color_selection_get_type ())

#define GIMP_COLOR_SELECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_SELECT, GimpColorSelect))
#define GIMP_IS_COLOR_SELECT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_SELECT))
#define GIMP_TYPE_COLOR_SELECT            (gimp_color_select_get_type ())

#define GIMP_COLOR_SELECTOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_SELECTOR, GimpColorSelector))
#define GIMP_COLOR_SELECTOR_BAR_SIZE 15
#define GIMP_COLOR_SELECTOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_SELECTOR, GimpColorSelectorClass))
#define GIMP_COLOR_SELECTOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_SELECTOR, GimpColorSelectorClass))
#define GIMP_COLOR_SELECTOR_SIZE     150
#define GIMP_IS_COLOR_SELECTOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_SELECTOR))
#define GIMP_IS_COLOR_SELECTOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_SELECTOR))
#define GIMP_TYPE_COLOR_SELECTOR            (gimp_color_selector_get_type ())

#define GIMP_COLOR_SCALES(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_SCALES, GimpColorScales))
#define GIMP_IS_COLOR_SCALES(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_SCALES))
#define GIMP_TYPE_COLOR_SCALES            (gimp_color_scales_get_type ())

#define GIMP_COLOR_SCALE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_SCALE, GimpColorScale))
#define GIMP_COLOR_SCALE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_SCALE, GimpColorScaleClass))
#define GIMP_COLOR_SCALE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_SCALE, GimpColorScaleClass))
#define GIMP_IS_COLOR_SCALE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_SCALE))
#define GIMP_IS_COLOR_SCALE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_SCALE))
#define GIMP_TYPE_COLOR_SCALE            (gimp_color_scale_get_type ())

#define GIMP_COLOR_PROFILE_VIEW(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_PROFILE_VIEW, GimpColorProfileView))
#define GIMP_COLOR_PROFILE_VIEW_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_PROFILE_VIEW, GimpColorProfileViewClass))
#define GIMP_COLOR_PROFILE_VIEW_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_PROFILE_VIEW, GimpColorProfileViewClass))
#define GIMP_IS_COLOR_PROFILE_VIEW(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_PROFILE_VIEW))
#define GIMP_IS_COLOR_PROFILE_VIEW_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_PROFILE_VIEW))
#define GIMP_TYPE_COLOR_PROFILE_VIEW            (gimp_color_profile_view_get_type ())

#define GIMP_COLOR_PROFILE_STORE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_PROFILE_STORE, GimpColorProfileStore))
#define GIMP_COLOR_PROFILE_STORE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_PROFILE_STORE, GimpColorProfileStoreClass))
#define GIMP_COLOR_PROFILE_STORE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_PROFILE_STORE, GimpColorProfileStoreClass))
#define GIMP_IS_COLOR_PROFILE_STORE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_PROFILE_STORE))
#define GIMP_IS_COLOR_PROFILE_STORE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_PROFILE_STORE))
#define GIMP_TYPE_COLOR_PROFILE_STORE            (gimp_color_profile_store_get_type ())

#define GIMP_COLOR_PROFILE_COMBO_BOX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_PROFILE_COMBO_BOX, GimpColorProfileComboBox))
#define GIMP_COLOR_PROFILE_COMBO_BOX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_PROFILE_COMBO_BOX, GimpColorProfileComboBoxClass))
#define GIMP_COLOR_PROFILE_COMBO_BOX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_PROFILE_COMBO_BOX, GimpColorProfileComboBoxClass))
#define GIMP_IS_COLOR_PROFILE_COMBO_BOX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_PROFILE_COMBO_BOX))
#define GIMP_IS_COLOR_PROFILE_COMBO_BOX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_PROFILE_COMBO_BOX))
#define GIMP_TYPE_COLOR_PROFILE_COMBO_BOX            (gimp_color_profile_combo_box_get_type ())

#define GIMP_COLOR_PROFILE_CHOOSER_DIALOG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_PROFILE_CHOOSER_DIALOG, GimpColorProfileChooserDialog))
#define GIMP_COLOR_PROFILE_CHOOSER_DIALOG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_PROFILE_CHOOSER_DIALOG, GimpColorProfileChooserDialogClass))
#define GIMP_COLOR_PROFILE_CHOOSER_DIALOG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_PROFILE_CHOOSER_DIALOG, GimpColorProfileChooserDialogClass))
#define GIMP_IS_COLOR_PROFILE_CHOOSER_DIALOG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_PROFILE_CHOOSER_DIALOG))
#define GIMP_IS_COLOR_PROFILE_CHOOSER_DIALOG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_PROFILE_CHOOSER_DIALOG))
#define GIMP_TYPE_COLOR_PROFILE_CHOOSER_DIALOG            (gimp_color_profile_chooser_dialog_get_type ())

#define GIMP_COLOR_NOTEBOOK(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_NOTEBOOK, GimpColorNotebook))
#define GIMP_COLOR_NOTEBOOK_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_NOTEBOOK, GimpColorNotebookClass))
#define GIMP_COLOR_NOTEBOOK_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_NOTEBOOK, GimpColorNotebookClass))
#define GIMP_IS_COLOR_NOTEBOOK(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_NOTEBOOK))
#define GIMP_IS_COLOR_NOTEBOOK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_NOTEBOOK))
#define GIMP_TYPE_COLOR_NOTEBOOK            (gimp_color_notebook_get_type ())

#define GIMP_COLOR_HEX_ENTRY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_HEX_ENTRY, GimpColorHexEntry))
#define GIMP_COLOR_HEX_ENTRY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_HEX_ENTRY, GimpColorHexEntryClass))
#define GIMP_COLOR_HEX_ENTRY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_HEX_AREA, GimpColorHexEntryClass))
#define GIMP_IS_COLOR_HEX_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_HEX_ENTRY))
#define GIMP_IS_COLOR_HEX_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_HEX_ENTRY))
#define GIMP_TYPE_COLOR_HEX_ENTRY            (gimp_color_hex_entry_get_type ())

#define GIMP_COLOR_DISPLAY_STACK(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_DISPLAY_STACK, GimpColorDisplayStack))
#define GIMP_COLOR_DISPLAY_STACK_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_DISPLAY_STACK, GimpColorDisplayStackClass))
#define GIMP_COLOR_DISPLAY_STACK_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_DISPLAY_STACK, GimpColorDisplayStackClass))
#define GIMP_IS_COLOR_DISPLAY_STACK(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_DISPLAY_STACK))
#define GIMP_IS_COLOR_DISPLAY_STACK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_DISPLAY_STACK))
#define GIMP_TYPE_COLOR_DISPLAY_STACK            (gimp_color_display_stack_get_type ())

#define GIMP_COLOR_DISPLAY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_DISPLAY, GimpColorDisplay))
#define GIMP_COLOR_DISPLAY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_DISPLAY, GimpColorDisplayClass))
#define GIMP_COLOR_DISPLAY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_DISPLAY, GimpColorDisplayClass))
#define GIMP_IS_COLOR_DISPLAY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_DISPLAY))
#define GIMP_IS_COLOR_DISPLAY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_DISPLAY))
#define GIMP_TYPE_COLOR_DISPLAY            (gimp_color_display_get_type ())

#define GIMP_COLOR_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_BUTTON, GimpColorButton))
#define GIMP_COLOR_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_BUTTON, GimpColorButtonClass))
#define GIMP_COLOR_BUTTON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_BUTTON, GimpColorButtonClass))
#define GIMP_IS_COLOR_BUTTON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_BUTTON))
#define GIMP_IS_COLOR_BUTTON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_BUTTON))
#define GIMP_TYPE_COLOR_BUTTON            (gimp_color_button_get_type ())

#define GIMP_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_BUTTON, GimpButton))
#define GIMP_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_BUTTON, GimpButtonClass))
#define GIMP_BUTTON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_BUTTON, GimpButtonClass))
#define GIMP_IS_BUTTON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_BUTTON))
#define GIMP_IS_BUTTON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_BUTTON))
#define GIMP_TYPE_BUTTON            (gimp_button_get_type ())

#define GIMP_COLOR_AREA(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_AREA, GimpColorArea))
#define GIMP_COLOR_AREA_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_AREA, GimpColorAreaClass))
#define GIMP_COLOR_AREA_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_AREA, GimpColorAreaClass))
#define GIMP_IS_COLOR_AREA(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_AREA))
#define GIMP_IS_COLOR_AREA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_AREA))
#define GIMP_TYPE_COLOR_AREA            (gimp_color_area_get_type ())

#define GIMP_CHAIN_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_CHAIN_BUTTON, GimpChainButton))
#define GIMP_CHAIN_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_CHAIN_BUTTON, GimpChainButtonClass))
#define GIMP_CHAIN_BUTTON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_CHAIN_BUTTON, GimpChainButtonClass))
#define GIMP_IS_CHAIN_BUTTON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_CHAIN_BUTTON))
#define GIMP_IS_CHAIN_BUTTON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_CHAIN_BUTTON))
#define GIMP_TYPE_CHAIN_BUTTON            (gimp_chain_button_get_type ())

#define GIMP_CELL_RENDERER_TOGGLE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_CELL_RENDERER_TOGGLE, GimpCellRendererToggle))
#define GIMP_CELL_RENDERER_TOGGLE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_CELL_RENDERER_TOGGLE, GimpCellRendererToggleClass))
#define GIMP_CELL_RENDERER_TOGGLE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_CELL_RENDERER_TOGGLE, GimpCellRendererToggleClass))
#define GIMP_IS_CELL_RENDERER_TOGGLE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_CELL_RENDERER_TOGGLE))
#define GIMP_IS_CELL_RENDERER_TOGGLE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_CELL_RENDERER_TOGGLE))
#define GIMP_TYPE_CELL_RENDERER_TOGGLE            (gimp_cell_renderer_toggle_get_type ())

#define GIMP_CELL_RENDERER_COLOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_CELL_RENDERER_COLOR, GimpCellRendererColor))
#define GIMP_CELL_RENDERER_COLOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_CELL_RENDERER_COLOR, GimpCellRendererColorClass))
#define GIMP_CELL_RENDERER_COLOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_CELL_RENDERER_COLOR, GimpCellRendererColorClass))
#define GIMP_IS_CELL_RENDERER_COLOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_CELL_RENDERER_COLOR))
#define GIMP_IS_CELL_RENDERER_COLOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_CELL_RENDERER_COLOR))
#define GIMP_TYPE_CELL_RENDERER_COLOR            (gimp_cell_renderer_color_get_type ())


#define GIMP_BROWSER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_BROWSER, GimpBrowser))
#define GIMP_BROWSER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_BROWSER, GimpBrowserClass))
#define GIMP_BROWSER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_BROWSER, GimpBrowserClass))
#define GIMP_IS_BROWSER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_BROWSER))
#define GIMP_IS_BROWSER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_BROWSER))
#define GIMP_TYPE_BROWSER            (gimp_browser_get_type ())

#  define MAIN()                                        \
   struct HINSTANCE__;                                  \
                                                        \
   int _stdcall                                         \
   WinMain (struct HINSTANCE__ *hInstance,              \
            struct HINSTANCE__ *hPrevInstance,          \
            char *lpszCmdLine,                          \
            int   nCmdShow);                            \
                                                        \
   int _stdcall                                         \
   WinMain (struct HINSTANCE__ *hInstance,              \
            struct HINSTANCE__ *hPrevInstance,          \
            char *lpszCmdLine,                          \
            int   nCmdShow)                             \
   {                                                    \
     return gimp_main (&PLUG_IN_INFO, __argc, __argv);  \
   }                                                    \
                                                        \
   int                                                  \
   main (int argc, char *argv[])                        \
   {                                                    \
     						\
     return gimp_main (&PLUG_IN_INFO, __argc, __argv);  \
   }


#      define _stdcall __attribute__((stdcall))
#define gimp_get_data         gimp_procedural_db_get_data
#define gimp_get_data_size    gimp_procedural_db_get_data_size
#define gimp_set_data         gimp_procedural_db_set_data



















































































#define GIMP_TYPE_BRUSH_APPLICATION_MODE (gimp_brush_application_mode_get_type ())
#define GIMP_TYPE_CONVERT_DITHER_TYPE (gimp_convert_dither_type_get_type ())
#define GIMP_TYPE_HISTOGRAM_CHANNEL (gimp_histogram_channel_get_type ())
#define GIMP_TYPE_LAYER_MODE_EFFECTS (gimp_layer_mode_effects_get_type ())

#define CLAMP0255(a)  CLAMP(a,0,255)
#define MAX255(a)  ((a) | (((a) & 256) - (((a) & 256) >> 8)))
#define RINT(x) rint(x)
#define ROUND(x) ((int) ((x) + 0.5))
#define SIGNED_ROUND(x) ((int) ((((x) < 0) ? (x) - 0.5 : (x) + 0.5)))
#define SQR(x) ((x) * (x))


#define gimp_deg_to_rad(angle) ((angle) * (2.0 * G_PI) / 360.0)
#define gimp_rad_to_deg(angle) ((angle) * 360.0 / (2.0 * G_PI))


#define GIMP_IS_PARAM_SPEC_MATRIX2(pspec)  (G_TYPE_CHECK_INSTANCE_TYPE ((pspec), GIMP_TYPE_PARAM_MATRIX2))
#define GIMP_IS_PARAM_SPEC_MATRIX3(pspec)  (G_TYPE_CHECK_INSTANCE_TYPE ((pspec), GIMP_TYPE_PARAM_MATRIX3))
#define GIMP_TYPE_MATRIX2               (gimp_matrix2_get_type ())
#define GIMP_TYPE_MATRIX3               (gimp_matrix3_get_type ())
#define GIMP_TYPE_PARAM_MATRIX2            (gimp_param_matrix2_get_type ())
#define GIMP_TYPE_PARAM_MATRIX3            (gimp_param_matrix3_get_type ())
#define GIMP_VALUE_HOLDS_MATRIX2(value) (G_TYPE_CHECK_VALUE_TYPE ((value), GIMP_TYPE_MATRIX2))
#define GIMP_VALUE_HOLDS_MATRIX3(value) (G_TYPE_CHECK_VALUE_TYPE ((value), GIMP_TYPE_MATRIX3))



#define GIMP_COLOR_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_CONFIG, GimpColorConfig))
#define GIMP_COLOR_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_CONFIG, GimpColorConfigClass))
#define GIMP_IS_COLOR_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_CONFIG))
#define GIMP_IS_COLOR_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_CONFIG))
#define GIMP_TYPE_COLOR_CONFIG            (gimp_color_config_get_type ())


#define GIMP_IS_PARAM_SPEC_CONFIG_PATH(pspec) (G_TYPE_CHECK_INSTANCE_TYPE ((pspec), GIMP_TYPE_PARAM_CONFIG_PATH))
#define GIMP_TYPE_CONFIG_PATH               (gimp_config_path_get_type ())
#define GIMP_TYPE_PARAM_CONFIG_PATH            (gimp_param_config_path_get_type ())
#define GIMP_VALUE_HOLDS_CONFIG_PATH(value) (G_TYPE_CHECK_VALUE_TYPE ((value), GIMP_TYPE_CONFIG_PATH))

#define GIMP_CONFIG_INSTALL_PROP_BOOLEAN(class, id, name, blurb, default, flags) \
  GIMP_CONFIG_PROP_BOOLEAN(class, id, name, NULL, blurb, default, flags);
#define GIMP_CONFIG_INSTALL_PROP_BOXED(class, id, name, blurb, boxed_type, flags) \
  GIMP_CONFIG_PROP_BOXED(class, id, name, NULL, blurb, boxed_type, flags)
#define GIMP_CONFIG_INSTALL_PROP_DOUBLE(class, id, name, blurb, min, max, default, flags) \
  GIMP_CONFIG_PROP_DOUBLE(class, id, name, NULL, blurb, min, max, default, flags)
#define GIMP_CONFIG_INSTALL_PROP_ENUM(class, id, name, blurb, enum_type, default, flags) \
  GIMP_CONFIG_PROP_ENUM(class, id, name, NULL, blurb, enum_type, default, flags)
#define GIMP_CONFIG_INSTALL_PROP_INT(class, id, name, blurb, min, max, default, flags) \
  GIMP_CONFIG_PROP_INT(class, id, name, NULL, blurb, min, max, default, flags)
#define GIMP_CONFIG_INSTALL_PROP_MATRIX2(class, id, name, blurb, default, flags) \
  GIMP_CONFIG_PROP_MATRIX2(class, id, name, NULL, blurb, default, flags)
#define GIMP_CONFIG_INSTALL_PROP_MEMSIZE(class, id, name, blurb, min, max, default, flags) \
  GIMP_CONFIG_PROP_MEMSIZE(class, id, name, NULL, blurb, min, max, default, flags)
#define GIMP_CONFIG_INSTALL_PROP_OBJECT(class, id, name, blurb, object_type, flags) \
  GIMP_CONFIG_PROP_OBJECT(class, id, name, NULL, blurb, object_type, flags)
#define GIMP_CONFIG_INSTALL_PROP_PATH(class, id, name, blurb, path_type, default, flags) \
  GIMP_CONFIG_PROP_PATH(class, id, name, NULL, blurb, path_type, default, flags)
#define GIMP_CONFIG_INSTALL_PROP_POINTER(class, id, name, blurb, flags) \
  GIMP_CONFIG_PROP_POINTER(class, id, name, NULL, blurb, flags)
#define GIMP_CONFIG_INSTALL_PROP_RESOLUTION(class, id, name, blurb, default, flags) \
  GIMP_CONFIG_PROP_RESOLUTION(class, id, name, NULL, blurb, default, flags)
#define GIMP_CONFIG_INSTALL_PROP_RGB(class, id, name, blurb, has_alpha, default, flags) \
  GIMP_CONFIG_PROP_RGB(class, id, name, NULL, blurb, has_alpha, default, flags)
#define GIMP_CONFIG_INSTALL_PROP_STRING(class, id, name, blurb, default, flags) \
  GIMP_CONFIG_PROP_STRING(class, id, name, NULL, blurb, default, flags)
#define GIMP_CONFIG_INSTALL_PROP_UINT(class, id, name, blurb, min, max, default, flags) \
  GIMP_CONFIG_PROP_UINT(class, id, name, NULL, blurb, min, max, default, flags)
#define GIMP_CONFIG_INSTALL_PROP_UNIT(class, id, name, blurb, pixels, percent, default, flags) \
  GIMP_CONFIG_PROP_UNIT(class, id, name, NULL, blurb, pixels, percent, default, flags)
#define GIMP_CONFIG_PARAM_AGGREGATE    (1 << (1 + G_PARAM_USER_SHIFT))
#define GIMP_CONFIG_PARAM_CONFIRM      (1 << (3 + G_PARAM_USER_SHIFT))
#define GIMP_CONFIG_PARAM_DEFAULTS     (1 << (4 + G_PARAM_USER_SHIFT))
#define GIMP_CONFIG_PARAM_FLAGS (G_PARAM_READWRITE | \
                                 G_PARAM_CONSTRUCT | \
                                 GIMP_CONFIG_PARAM_SERIALIZE)
#define GIMP_CONFIG_PARAM_IGNORE       (1 << (5 + G_PARAM_USER_SHIFT))
#define GIMP_CONFIG_PARAM_RESTART      (1 << (2 + G_PARAM_USER_SHIFT))
#define GIMP_CONFIG_PARAM_SERIALIZE    (1 << (0 + G_PARAM_USER_SHIFT))
#define GIMP_CONFIG_PROP_BOOLEAN(class, id, name, nick, blurb, default, flags) \
  g_object_class_install_property (class, id,\
                                   g_param_spec_boolean (name, nick, blurb,\
                                   default,\
                                   flags | GIMP_CONFIG_PARAM_FLAGS))
#define GIMP_CONFIG_PROP_BOXED(class, id, name, nick, blurb, boxed_type, flags) \
  g_object_class_install_property (class, id,\
                                   g_param_spec_boxed (name, nick, blurb,\
                                   boxed_type,\
                                   flags |\
                                   G_PARAM_READWRITE |\
                                   GIMP_CONFIG_PARAM_SERIALIZE))
#define GIMP_CONFIG_PROP_DOUBLE(class, id, name, nick, blurb, min, max, default, flags) \
  g_object_class_install_property (class, id,\
                                   g_param_spec_double (name, nick, blurb,\
                                   min, max, default,\
                                   flags | GIMP_CONFIG_PARAM_FLAGS))
#define GIMP_CONFIG_PROP_ENUM(class, id, name, nick, blurb, enum_type, default, flags) \
  g_object_class_install_property (class, id,\
                                   g_param_spec_enum (name, nick, blurb,\
                                   enum_type, default,\
                                   flags | GIMP_CONFIG_PARAM_FLAGS))
#define GIMP_CONFIG_PROP_INT(class, id, name, nick, blurb, min, max, default, flags) \
  g_object_class_install_property (class, id,\
                                   g_param_spec_int (name, nick, blurb,\
                                   min, max, default,\
                                   flags | GIMP_CONFIG_PARAM_FLAGS))
#define GIMP_CONFIG_PROP_MATRIX2(class, id, name, nick, blurb, default, flags) \
  g_object_class_install_property (class, id,\
                                   gimp_param_spec_matrix2 (name, nick, blurb,\
                                   default,\
                                   flags | GIMP_CONFIG_PARAM_FLAGS))
#define GIMP_CONFIG_PROP_MEMSIZE(class, id, name, nick, blurb, min, max, default, flags) \
  g_object_class_install_property (class, id,\
                                   gimp_param_spec_memsize (name, nick, blurb,\
                                   min, max, default,\
                                   flags | GIMP_CONFIG_PARAM_FLAGS))
#define GIMP_CONFIG_PROP_OBJECT(class, id, name, nick, blurb, object_type, flags) \
  g_object_class_install_property (class, id,\
                                   g_param_spec_object (name, nick, blurb,\
                                   object_type,\
                                   flags |\
                                   G_PARAM_READWRITE |\
                                   GIMP_CONFIG_PARAM_SERIALIZE))
#define GIMP_CONFIG_PROP_PATH(class, id, name, nick, blurb, path_type, default, flags) \
  g_object_class_install_property (class, id,\
                                   gimp_param_spec_config_path (name, nick, blurb,\
                                   path_type, default,\
                                   flags | GIMP_CONFIG_PARAM_FLAGS))
#define GIMP_CONFIG_PROP_POINTER(class, id, name, nick, blurb, flags)    \
  g_object_class_install_property (class, id,\
                                   g_param_spec_pointer (name, nick, blurb,\
                                   flags |\
                                   G_PARAM_READWRITE |\
                                   GIMP_CONFIG_PARAM_SERIALIZE))
#define GIMP_CONFIG_PROP_RESOLUTION(class, id, name, nick, blurb, default, flags) \
  g_object_class_install_property (class, id,\
                                   g_param_spec_double (name, nick, blurb,\
                                   GIMP_MIN_RESOLUTION, GIMP_MAX_RESOLUTION, \
                                   default,\
                                   flags | GIMP_CONFIG_PARAM_FLAGS))
#define GIMP_CONFIG_PROP_RGB(class, id, name, nick, blurb, has_alpha, default, flags) \
  g_object_class_install_property (class, id,\
                                   gimp_param_spec_rgb (name, nick, blurb,\
                                   has_alpha, default, \
                                   flags | GIMP_CONFIG_PARAM_FLAGS))
#define GIMP_CONFIG_PROP_STRING(class, id, name, nick, blurb, default, flags) \
  g_object_class_install_property (class, id,\
                                   g_param_spec_string (name, nick, blurb,\
                                   default,\
                                   flags | GIMP_CONFIG_PARAM_FLAGS))
#define GIMP_CONFIG_PROP_UINT(class, id, name, nick, blurb, min, max, default, flags) \
  g_object_class_install_property (class, id,\
                                   g_param_spec_uint (name, nick, blurb,\
                                   min, max, default,\
                                   flags | GIMP_CONFIG_PARAM_FLAGS))
#define GIMP_CONFIG_PROP_UNIT(class, id, name, nick, blurb, pixels, percent, default, flags) \
  g_object_class_install_property (class, id,\
                                   gimp_param_spec_unit (name, nick, blurb,\
                                   pixels, percent, default,\
                                   flags | GIMP_CONFIG_PARAM_FLAGS))




#define GIMP_CONFIG_ERROR (gimp_config_error_quark ())

#define GIMP_CONFIG(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_CONFIG, GimpConfig))
#define GIMP_CONFIG_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), GIMP_TYPE_CONFIG, GimpConfigInterface))
#define GIMP_IS_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_CONFIG))
#define GIMP_TYPE_CONFIG               (gimp_config_interface_get_type ())




#define GIMP_IS_PARAM_SPEC_RGB(pspec) (G_TYPE_CHECK_INSTANCE_TYPE ((pspec), GIMP_TYPE_PARAM_RGB))
#define GIMP_RGB_INTENSITY(r,g,b) ((r) * GIMP_RGB_INTENSITY_RED   + \
                                   (g) * GIMP_RGB_INTENSITY_GREEN + \
                                   (b) * GIMP_RGB_INTENSITY_BLUE)
#define GIMP_RGB_INTENSITY_BLUE   (0.11)
#define GIMP_RGB_INTENSITY_GREEN  (0.59)
#define GIMP_RGB_INTENSITY_RED    (0.30)
#define GIMP_RGB_LUMINANCE(r,g,b) ((r) * GIMP_RGB_LUMINANCE_RED   + \
                                   (g) * GIMP_RGB_LUMINANCE_GREEN + \
                                   (b) * GIMP_RGB_LUMINANCE_BLUE)
#define GIMP_RGB_LUMINANCE_BLUE   (0.06060791)
#define GIMP_RGB_LUMINANCE_GREEN  (0.71690369)
#define GIMP_RGB_LUMINANCE_RED    (0.22248840)
#define GIMP_TYPE_PARAM_RGB           (gimp_param_rgb_get_type ())
#define GIMP_TYPE_RGB               (gimp_rgb_get_type ())
#define GIMP_VALUE_HOLDS_RGB(value) (G_TYPE_CHECK_VALUE_TYPE ((value), GIMP_TYPE_RGB))


#define GIMP_TYPE_HSV       (gimp_hsv_get_type ())

#define GIMP_TYPE_HSL       (gimp_hsl_get_type ())

#define GIMP_TYPE_CMYK       (gimp_cmyk_get_type ())

#define GIMP_COLOR_TRANSFORM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_TRANSFORM, GimpColorTransform))
#define GIMP_COLOR_TRANSFORM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_TRANSFORM, GimpColorTransformClass))
#define GIMP_COLOR_TRANSFORM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_TRANSFORM, GimpColorTransformClass))
#define GIMP_IS_COLOR_TRANSFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_TRANSFORM))
#define GIMP_IS_COLOR_TRANSFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_TRANSFORM))
#define GIMP_TYPE_COLOR_TRANSFORM            (gimp_color_transform_get_type ())


#define GIMP_COLOR_PROFILE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_PROFILE, GimpColorProfile))
#define GIMP_COLOR_PROFILE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_COLOR_PROFILE, GimpColorProfileClass))
#define GIMP_COLOR_PROFILE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_COLOR_PROFILE, GimpColorProfileClass))
#define GIMP_IS_COLOR_PROFILE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_PROFILE))
#define GIMP_IS_COLOR_PROFILE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_COLOR_PROFILE))
#define GIMP_TYPE_COLOR_PROFILE            (gimp_color_profile_get_type ())

#define GIMP_COLOR_MANAGED(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_COLOR_MANAGED, GimpColorManaged))
#define GIMP_COLOR_MANAGED_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), GIMP_TYPE_COLOR_MANAGED, GimpColorManagedInterface))
#define GIMP_IS_COLOR_MANAGED(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_COLOR_MANAGED))
#define GIMP_TYPE_COLOR_MANAGED               (gimp_color_managed_interface_get_type ())

#define GIMP_CAIRO_ARGB32_GET_PIXEL(s, r, g, b, a) \
  G_STMT_START {                                   \
    const guint tb = (s)[0];                       \
    const guint tg = (s)[1];                       \
    const guint tr = (s)[2];                       \
    const guint ta = (s)[3];                       \
    (r) = (tr << 8) / (ta + 1);                    \
    (g) = (tg << 8) / (ta + 1);                    \
    (b) = (tb << 8) / (ta + 1);                    \
    (a) = ta;                                      \
  } G_STMT_END
#define GIMP_CAIRO_ARGB32_SET_PIXEL(d, r, g, b, a) \
  G_STMT_START {                                   \
    const guint tr = (a) * (r) + 0x80;             \
    const guint tg = (a) * (g) + 0x80;             \
    const guint tb = (a) * (b) + 0x80;             \
    (d)[0] = (a);                                  \
    (d)[1] = (((tr) >> 8) + (tr)) >> 8;            \
    (d)[2] = (((tg) >> 8) + (tg)) >> 8;            \
    (d)[3] = (((tb) >> 8) + (tb)) >> 8;            \
  } G_STMT_END
#define GIMP_CAIRO_RGB24_GET_PIXEL(s, r, g, b) \
  G_STMT_START { (b) = s[0]; (g) = s[1]; (r) = s[2]; } G_STMT_END
#define GIMP_CAIRO_RGB24_SET_PIXEL(d, r, g, b) \
  G_STMT_START { d[0] = (b);  d[1] = (g);  d[2] = (r); } G_STMT_END






#define GIMP_IS_PARAM_SPEC_VALUE_ARRAY(pspec) (G_TYPE_CHECK_INSTANCE_TYPE ((pspec), GIMP_TYPE_PARAM_VALUE_ARRAY))
#define GIMP_PARAM_SPEC_VALUE_ARRAY(pspec)    (G_TYPE_CHECK_INSTANCE_CAST ((pspec), GIMP_TYPE_PARAM_VALUE_ARRAY, GimpParamSpecValueArray))
#define GIMP_TYPE_PARAM_VALUE_ARRAY           (gimp_param_value_array_get_type ())
#define GIMP_TYPE_VALUE_ARRAY (gimp_value_array_get_type ())


#define GIMP_IS_PARAM_SPEC_UNIT(pspec)    (G_TYPE_CHECK_INSTANCE_TYPE ((pspec), GIMP_TYPE_PARAM_UNIT))
#define GIMP_TYPE_PARAM_UNIT              (gimp_param_unit_get_type ())
#define GIMP_TYPE_UNIT               (gimp_unit_get_type ())
#define GIMP_VALUE_HOLDS_UNIT(value) (G_TYPE_CHECK_VALUE_TYPE ((value), GIMP_TYPE_UNIT))


#define GIMP_IS_PARAM_SPEC_PARASITE(pspec) (G_TYPE_CHECK_INSTANCE_TYPE ((pspec), GIMP_TYPE_PARAM_PARASITE))
#define GIMP_PARASITE_ATTACH_GRANDPARENT     (0x80 << 16)
#define GIMP_PARASITE_ATTACH_PARENT     (0x80 << 8)
#define GIMP_PARASITE_GRANDPARENT_PERSISTENT (GIMP_PARASITE_PERSISTENT << 16)
#define GIMP_PARASITE_GRANDPARENT_UNDOABLE   (GIMP_PARASITE_UNDOABLE << 16)
#define GIMP_PARASITE_PARENT_PERSISTENT (GIMP_PARASITE_PERSISTENT << 8)
#define GIMP_PARASITE_PARENT_UNDOABLE   (GIMP_PARASITE_UNDOABLE << 8)
#define GIMP_PARASITE_PERSISTENT 1
#define GIMP_PARASITE_UNDOABLE   2
#define GIMP_TYPE_PARAM_PARASITE           (gimp_param_parasite_get_type ())
#define GIMP_TYPE_PARASITE               (gimp_parasite_get_type ())
#define GIMP_VALUE_HOLDS_PARASITE(value) (G_TYPE_CHECK_VALUE_TYPE ((value), GIMP_TYPE_PARASITE))


#define GIMP_IS_PARAM_SPEC_MEMSIZE(pspec) (G_TYPE_CHECK_INSTANCE_TYPE ((pspec), GIMP_TYPE_PARAM_MEMSIZE))
#define GIMP_TYPE_MEMSIZE               (gimp_memsize_get_type ())
#define GIMP_TYPE_PARAM_MEMSIZE           (gimp_param_memsize_get_type ())
#define GIMP_VALUE_HOLDS_MEMSIZE(value) (G_TYPE_CHECK_VALUE_TYPE ((value), GIMP_TYPE_MEMSIZE))

#define GIMP_MAX_IMAGE_SIZE  524288    
#define GIMP_MAX_MEMSIZE     ((guint64) 1 << 42) 
#define GIMP_MAX_RESOLUTION  1048576.0
#define GIMP_MIN_IMAGE_SIZE  1
#define GIMP_MIN_RESOLUTION  5e-3      

#    define GIMPVAR __declspec(dllexport)



#define GIMP_CHECK_DARK   0.4
#define GIMP_CHECK_LIGHT  0.6
#define GIMP_CHECK_SIZE     8
#define GIMP_CHECK_SIZE_SM  4

