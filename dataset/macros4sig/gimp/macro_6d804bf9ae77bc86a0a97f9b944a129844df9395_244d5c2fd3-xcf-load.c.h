#include<string.h>









#include<time.h>


#include<zlib.h>









#include<signal.h>




#define AUTO_TAB_STYLE     GIMP_LOG_AUTO_TAB_STYLE
#define BRUSH_CACHE        GIMP_LOG_BRUSH_CACHE
#define DIALOG_FACTORY     GIMP_LOG_DIALOG_FACTORY
#define DND                GIMP_LOG_DND
#define FLOATING_SELECTION GIMP_LOG_FLOATING_SELECTION
#define GIMP_LOG(type, ...) \
        G_STMT_START { \
        if (gimp_log_flags & GIMP_LOG_##type) \
          gimp_log (GIMP_LOG_##type, G_STRFUNC, "__LINE__", __VA_ARGS__);       \
        } G_STMT_END
#define HELP               GIMP_LOG_HELP
#define IMAGE_SCALE        GIMP_LOG_IMAGE_SCALE
#define INSTANCES          GIMP_LOG_INSTANCES
#define KEY_EVENTS         GIMP_LOG_KEY_EVENTS
#define MENUS              GIMP_LOG_MENUS
#define PROJECTION         GIMP_LOG_PROJECTION
#define RECTANGLE_TOOL     GIMP_LOG_RECTANGLE_TOOL
#define SAVE_DIALOG        GIMP_LOG_SAVE_DIALOG
#define SCALE              GIMP_LOG_SCALE
#define SHADOW_TILES       GIMP_LOG_SHADOW_TILES
#define SHM                GIMP_LOG_SHM
#define TEXT_EDITING       GIMP_LOG_TEXT_EDITING
#define TOOL_EVENTS        GIMP_LOG_TOOL_EVENTS
#define TOOL_FOCUS         GIMP_LOG_TOOL_FOCUS
#define WM                 GIMP_LOG_WM
#define XCF                GIMP_LOG_XCF

#define fnord(kosmoso)   void gimp_##kosmoso##bl_dialog(void);
#define geimnum(vienna)  gimp_l##vienna##l_dialog()



#define XCF_TILE_HEIGHT 64
#define XCF_TILE_WIDTH  64


#define GIMP_IS_VECTORS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_VECTORS))
#define GIMP_IS_VECTORS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_VECTORS))
#define GIMP_TYPE_VECTORS            (gimp_vectors_get_type ())
#define GIMP_VECTORS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_VECTORS, GimpVectors))
#define GIMP_VECTORS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_VECTORS, GimpVectorsClass))
#define GIMP_VECTORS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_VECTORS, GimpVectorsClass))

#define GIMP_IS_ITEM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_ITEM))
#define GIMP_IS_ITEM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_ITEM))
#define GIMP_ITEM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_ITEM, GimpItem))
#define GIMP_ITEM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_ITEM, GimpItemClass))
#define GIMP_ITEM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_ITEM, GimpItemClass))
#define GIMP_TYPE_ITEM            (gimp_item_get_type ())

#define GIMP_BEZIER_STROKE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_BEZIER_STROKE, GimpBezierStroke))
#define GIMP_BEZIER_STROKE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_BEZIER_STROKE, GimpBezierStrokeClass))
#define GIMP_BEZIER_STROKE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_BEZIER_STROKE, GimpBezierStrokeClass))
#define GIMP_IS_BEZIER_STROKE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_BEZIER_STROKE))
#define GIMP_IS_BEZIER_STROKE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_BEZIER_STROKE))
#define GIMP_TYPE_BEZIER_STROKE            (gimp_bezier_stroke_get_type ())

#define GIMP_IS_STROKE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_STROKE))
#define GIMP_IS_STROKE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_STROKE))
#define GIMP_STROKE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_STROKE, GimpStroke))
#define GIMP_STROKE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_STROKE, GimpStrokeClass))
#define GIMP_STROKE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_STROKE, GimpStrokeClass))
#define GIMP_TYPE_STROKE            (gimp_stroke_get_type ())

#define GIMP_IS_OBJECT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_OBJECT))
#define GIMP_IS_OBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_OBJECT))
#define GIMP_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_OBJECT, GimpObject))
#define GIMP_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_OBJECT, GimpObjectClass))
#define GIMP_OBJECT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_OBJECT, GimpObjectClass))
#define GIMP_TYPE_OBJECT            (gimp_object_get_type ())

#define GIMP_ANCHOR(anchor)  ((GimpAnchor *) (anchor))
#define GIMP_TYPE_ANCHOR               (gimp_anchor_get_type ())
#define GIMP_VALUE_HOLDS_ANCHOR(value) (G_TYPE_CHECK_VALUE_TYPE ((value), GIMP_TYPE_ANCHOR))


#define GIMP_IS_TEXT_LAYER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_TEXT_LAYER))
#define GIMP_IS_TEXT_LAYER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_TEXT_LAYER))
#define GIMP_TEXT_LAYER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_TEXT_LAYER, GimpTextLayer))
#define GIMP_TEXT_LAYER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_TEXT_LAYER, GimpTextLayerClass))
#define GIMP_TEXT_LAYER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_TEXT_LAYER, GimpTextLayerClass))
#define GIMP_TYPE_TEXT_LAYER            (gimp_text_layer_get_type ())

#define GIMP_IS_LAYER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_LAYER))
#define GIMP_IS_LAYER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_LAYER))
#define GIMP_LAYER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_LAYER, GimpLayer))
#define GIMP_LAYER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_LAYER, GimpLayerClass))
#define GIMP_LAYER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_LAYER, GimpLayerClass))
#define GIMP_TYPE_LAYER            (gimp_layer_get_type ())

#define GIMP_DEFAULT_IMAGE_HEIGHT  377
#define GIMP_DEFAULT_IMAGE_WIDTH   610
#define GIMP_IS_TEMPLATE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_TEMPLATE))
#define GIMP_IS_TEMPLATE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_TEMPLATE))
#define GIMP_TEMPLATE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_TEMPLATE, GimpTemplate))
#define GIMP_TEMPLATE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_TEMPLATE, GimpTemplateClass))
#define GIMP_TEMPLATE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_TEMPLATE, GimpTemplateClass))
#define GIMP_TEMPLATE_PARAM_COPY_FIRST (1 << (8 + G_PARAM_USER_SHIFT))
#define GIMP_TYPE_TEMPLATE            (gimp_template_get_type ())

#define GIMP_IS_SELECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_SELECTION))
#define GIMP_IS_SELECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_SELECTION))
#define GIMP_SELECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_SELECTION, GimpSelection))
#define GIMP_SELECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_SELECTION, GimpSelectionClass))
#define GIMP_SELECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_SELECTION, GimpSelectionClass))
#define GIMP_TYPE_SELECTION            (gimp_selection_get_type ())

#define GIMP_IS_PROGRESS(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_PROGRESS))
#define GIMP_PROGRESS(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_PROGRESS, GimpProgress))
#define GIMP_PROGRESS_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), GIMP_TYPE_PROGRESS, GimpProgressInterface))
#define GIMP_TYPE_PROGRESS               (gimp_progress_interface_get_type ())

#define GIMP_IS_PARASITE_LIST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_PARASITE_LIST))
#define GIMP_IS_PARASITE_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_PARASITE_LIST))
#define GIMP_PARASITE_LIST(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_PARASITE_LIST, GimpParasiteList))
#define GIMP_PARASITE_LIST_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_PARASITE_LIST, GimpParasiteListClass))
#define GIMP_PARASITE_LIST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_PARASITE_LIST, GimpParasiteListClass))
#define GIMP_TYPE_PARASITE_LIST            (gimp_parasite_list_get_type ())

#define GIMP_IS_LAYER_MASK(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_LAYER_MASK))
#define GIMP_IS_LAYER_MASK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_LAYER_MASK))
#define GIMP_LAYER_MASK(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_LAYER_MASK, GimpLayerMask))
#define GIMP_LAYER_MASK_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_LAYER_MASK, GimpLayerMaskClass))
#define GIMP_LAYER_MASK_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_LAYER_MASK, GimpLayerMaskClass))
#define GIMP_TYPE_LAYER_MASK            (gimp_layer_mask_get_type ())



#define GIMP_IS_ITEM_STACK(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_ITEM_STACK))
#define GIMP_IS_ITEM_STACK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_ITEM_STACK))
#define GIMP_ITEM_STACK(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_ITEM_STACK, GimpItemStack))
#define GIMP_ITEM_STACK_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_ITEM_STACK, GimpItemStackClass))
#define GIMP_TYPE_ITEM_STACK            (gimp_item_stack_get_type ())



#define GIMP_IMAGE_GET_PRIVATE(image) \
        G_TYPE_INSTANCE_GET_PRIVATE (image, \
                                     GIMP_TYPE_IMAGE, \
                                     GimpImagePrivate)




#define GIMP_IMAGE_COLORMAP_SIZE 768

#define GIMP_IMAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_IMAGE, GimpImage))
#define GIMP_IMAGE_ACTIVE_PARENT ((gpointer) 1)
#define GIMP_IMAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_IMAGE, GimpImageClass))
#define GIMP_IMAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_IMAGE, GimpImageClass))
#define GIMP_IS_IMAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_IMAGE))
#define GIMP_IS_IMAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_IMAGE))
#define GIMP_TYPE_IMAGE            (gimp_image_get_type ())

#define GIMP_GROUP_LAYER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_GROUP_LAYER, GimpGroupLayer))
#define GIMP_GROUP_LAYER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_GROUP_LAYER, GimpGroupLayerClass))
#define GIMP_GROUP_LAYER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_GROUP_LAYER, GimpGroupLayerClass))
#define GIMP_IS_GROUP_LAYER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_GROUP_LAYER))
#define GIMP_IS_GROUP_LAYER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_GROUP_LAYER))
#define GIMP_TYPE_GROUP_LAYER            (gimp_group_layer_get_type ())

#define GIMP_GRID(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_GRID, GimpGrid))
#define GIMP_GRID_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_GRID, GimpGridClass))
#define GIMP_GRID_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_GRID, GimpGridClass))
#define GIMP_IS_GRID(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_GRID))
#define GIMP_IS_GRID_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_GRID))
#define GIMP_TYPE_GRID            (gimp_grid_get_type ())


#define GIMP_CONTAINER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_CONTAINER, GimpContainer))
#define GIMP_CONTAINER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_CONTAINER, GimpContainerClass))
#define GIMP_CONTAINER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GIMP_TYPE_CONTAINER, GimpContainerClass))
#define GIMP_IS_CONTAINER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_CONTAINER))
#define GIMP_IS_CONTAINER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_CONTAINER))
#define GIMP_TYPE_CONTAINER            (gimp_container_get_type ())

#define GIMP(obj)                 (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_GIMP, Gimp))
#define GIMP_CLASS(klass)         (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_GIMP, GimpClass))
#define GIMP_IS_GIMP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_GIMP))
#define GIMP_IS_GIMP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_GIMP))
#define GIMP_TYPE_GIMP            (gimp_get_type ())


#define GIMP_CORE_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_CORE_CONFIG, GimpCoreConfig))
#define GIMP_CORE_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_CORE_CONFIG, GimpCoreConfigClass))
#define GIMP_IS_CORE_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_CORE_CONFIG))
#define GIMP_IS_CORE_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_CORE_CONFIG))
#define GIMP_TYPE_CORE_CONFIG            (gimp_core_config_get_type ())

#define GIMP_GEGL_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GIMP_TYPE_GEGL_CONFIG, GimpGeglConfig))
#define GIMP_GEGL_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GIMP_TYPE_GEGL_CONFIG, GimpGeglConfigClass))
#define GIMP_IS_GEGL_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GIMP_TYPE_GEGL_CONFIG))
#define GIMP_IS_GEGL_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GIMP_TYPE_GEGL_CONFIG))
#define GIMP_TYPE_GEGL_CONFIG            (gimp_gegl_config_get_type ())

#define GIMP_TYPE_ALIGNMENT_TYPE (gimp_alignment_type_get_type ())
#define GIMP_TYPE_ALIGN_REFERENCE_TYPE (gimp_align_reference_type_get_type ())
#define GIMP_TYPE_CHANNEL_BORDER_STYLE (gimp_channel_border_style_get_type ())
#define GIMP_TYPE_COLOR_PROFILE_POLICY (gimp_color_profile_policy_get_type ())
#define GIMP_TYPE_COMPONENT_MASK (gimp_component_mask_get_type ())
#define GIMP_TYPE_CONTAINER_POLICY (gimp_container_policy_get_type ())
#define GIMP_TYPE_CONVERT_DITHER_TYPE (gimp_convert_dither_type_get_type ())
#define GIMP_TYPE_CONVOLUTION_TYPE (gimp_convolution_type_get_type ())
#define GIMP_TYPE_CURVE_TYPE (gimp_curve_type_get_type ())
#define GIMP_TYPE_DASH_PRESET (gimp_dash_preset_get_type ())
#define GIMP_TYPE_DIRTY_MASK (gimp_dirty_mask_get_type ())
#define GIMP_TYPE_DYNAMICS_OUTPUT_TYPE (gimp_dynamics_output_type_get_type ())
#define GIMP_TYPE_FILL_STYLE (gimp_fill_style_get_type ())
#define GIMP_TYPE_FILTER_REGION (gimp_filter_region_get_type ())
#define GIMP_TYPE_GRADIENT_COLOR (gimp_gradient_color_get_type ())
#define GIMP_TYPE_GRAVITY_TYPE (gimp_gravity_type_get_type ())
#define GIMP_TYPE_GUIDE_STYLE (gimp_guide_style_get_type ())
#define GIMP_TYPE_HISTOGRAM_CHANNEL (gimp_histogram_channel_get_type ())
#define GIMP_TYPE_ITEM_SET (gimp_item_set_get_type ())
#define GIMP_TYPE_LAYER_MODE_EFFECTS (gimp_layer_mode_effects_get_type ())
#define GIMP_TYPE_MATTING_ENGINE (gimp_matting_engine_get_type ())
#define GIMP_TYPE_MESSAGE_SEVERITY (gimp_message_severity_get_type ())
#define GIMP_TYPE_THUMBNAIL_SIZE (gimp_thumbnail_size_get_type ())
#define GIMP_TYPE_UNDO_EVENT (gimp_undo_event_get_type ())
#define GIMP_TYPE_UNDO_MODE (gimp_undo_mode_get_type ())
#define GIMP_TYPE_UNDO_TYPE (gimp_undo_type_get_type ())
#define GIMP_TYPE_VIEW_SIZE (gimp_view_size_get_type ())
#define GIMP_TYPE_VIEW_TYPE (gimp_view_type_get_type ())

#define ALPHA         3
#define ALPHA_G       1
#define ALPHA_I       1
#define BLUE          2
#define GIMP_COORDS_DEFAULT_DIRECTION 0.0
#define GIMP_COORDS_DEFAULT_PRESSURE  1.0
#define GIMP_COORDS_DEFAULT_TILT      0.0
#define GIMP_COORDS_DEFAULT_VALUES    { 0.0, 0.0, \
                                        GIMP_COORDS_DEFAULT_PRESSURE, \
                                        GIMP_COORDS_DEFAULT_TILT,     \
                                        GIMP_COORDS_DEFAULT_TILT,     \
                                        GIMP_COORDS_DEFAULT_WHEEL,    \
                                        GIMP_COORDS_DEFAULT_VELOCITY, \
                                        GIMP_COORDS_DEFAULT_DIRECTION,\
                                        GIMP_COORDS_DEFAULT_XSCALE,   \
                                        GIMP_COORDS_DEFAULT_YSCALE }
#define GIMP_COORDS_DEFAULT_VELOCITY  0.0
#define GIMP_COORDS_DEFAULT_WHEEL     0.5
#define GIMP_COORDS_DEFAULT_XSCALE    1.0
#define GIMP_COORDS_DEFAULT_YSCALE    1.0
#define GIMP_COORDS_MAX_PRESSURE      1.0
#define GIMP_COORDS_MAX_TILT          1.0
#define GIMP_COORDS_MAX_WHEEL         1.0
#define GIMP_COORDS_MIN_PRESSURE      0.0
#define GIMP_COORDS_MIN_TILT         -1.0
#define GIMP_COORDS_MIN_WHEEL         0.0
#define GRAY          0
#define GREEN         1
#define INDEXED       0
#define MAX_CHANNELS  4
#define RED           0

#define GIMP_PLUG_IN_TILE_HEIGHT 128
#define GIMP_PLUG_IN_TILE_WIDTH  128

#define GIMP_TYPE_FILE_PROCEDURE_GROUP (gimp_file_procedure_group_get_type ())
#define GIMP_TYPE_PLUG_CALL_MODE (gimp_plug_in_call_mode_get_type ())
#define GIMP_TYPE_PLUG_IN_IMAGE_TYPE (gimp_plug_in_image_type_get_type ())





#define GIMP_TYPE_TEXT_BOX_MODE (gimp_text_box_mode_get_type ())
#define GIMP_TYPE_TEXT_OUTLINE (gimp_text_outline_get_type ())


#define GIMP_TYPE_BRUSH_APPLICATION_MODE (gimp_brush_application_mode_get_type ())
#define GIMP_TYPE_PERSPECTIVE_CLONE_MODE (gimp_perspective_clone_mode_get_type ())
#define GIMP_TYPE_SOURCE_ALIGN_MODE (gimp_source_align_mode_get_type ())



#define GIMP_TYPE_CAGE_MODE (gimp_cage_mode_get_type ())

#define GIMP_OPACITY_OPAQUE           1.0
#define GIMP_OPACITY_TRANSPARENT      0.0

#define GIMP_TYPE_CANVAS_PADDING_MODE (gimp_canvas_padding_mode_get_type ())
#define GIMP_TYPE_CURSOR_FORMAT (gimp_cursor_format_get_type ())
#define GIMP_TYPE_CURSOR_MODE (gimp_cursor_mode_get_type ())
#define GIMP_TYPE_HANDEDNESS (gimp_handedness_get_type ())
#define GIMP_TYPE_HELP_BROWSER_TYPE (gimp_help_browser_type_get_type ())
#define GIMP_TYPE_POSITION (gimp_position_get_type ())
#define GIMP_TYPE_SPACE_BAR_ACTION (gimp_space_bar_action_get_type ())
#define GIMP_TYPE_WINDOW_HINT (gimp_window_hint_get_type ())
#define GIMP_TYPE_ZOOM_QUALITY (gimp_zoom_quality_get_type ())


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




#define GIMP_TYPE_THUMB_FILE_TYPE (gimp_thumb_file_type_get_type ())
#define GIMP_TYPE_THUMB_SIZE (gimp_thumb_size_get_type ())
#define GIMP_TYPE_THUMB_STATE (gimp_thumb_state_get_type ())

#define GIMP_MODULE_PARAM_SERIALIZE (1 << (0 + G_PARAM_USER_SHIFT))



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

