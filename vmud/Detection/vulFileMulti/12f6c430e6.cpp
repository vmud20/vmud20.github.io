










namespace mkv {

event_thread_t::event_thread_t(demux_t *p_demux) : p_demux(p_demux)
{
    vlc_mutex_init( &lock );
    vlc_cond_init( &wait );
    is_running = false;
    memset(&pci_packet, 0, sizeof(pci_packet));
}
event_thread_t::~event_thread_t()
{
    ResetPci();
    vlc_cond_destroy( &wait );
    vlc_mutex_destroy( &lock );
}

void event_thread_t::SetPci(const pci_t *data)
{
    vlc_mutex_locker l(&lock);

    pci_packet = *data;


    for( uint8_t button = 1; button <= pci_packet.hli.hl_gi.btn_ns; button++) {
        btni_t *button_ptr = &(pci_packet.hli.btnit[button-1]);
        binary *p_data = (binary*) button_ptr;

        uint16 i_x_start = ((p_data[0] & 0x3F) << 4 ) + ( p_data[1] >> 4 );
        uint16 i_x_end   = ((p_data[1] & 0x03) << 8 ) + p_data[2];
        uint16 i_y_start = ((p_data[3] & 0x3F) << 4 ) + ( p_data[4] >> 4 );
        uint16 i_y_end   = ((p_data[4] & 0x03) << 8 ) + p_data[5];
        button_ptr->x_start = i_x_start;
        button_ptr->x_end   = i_x_end;
        button_ptr->y_start = i_y_start;
        button_ptr->y_end   = i_y_end;

    }
    for ( uint8_t i = 0; i<3; i++ )
        for ( uint8_t j = 0; j<2; j++ )
            pci_packet.hli.btn_colit.btn_coli[i][j] = U32_AT( &pci_packet.hli.btn_colit.btn_coli[i][j] );

    if( !is_running )
    {
        b_abort = false;
        is_running = !vlc_clone( &thread, EventThread, this, VLC_THREAD_PRIORITY_LOW );
    }
}
void event_thread_t::ResetPci()
{
    if( !is_running )
        return;

    vlc_mutex_lock( &lock );
    b_abort = true;
    vlc_cond_signal( &wait );
    vlc_mutex_unlock( &lock );

    vlc_join( thread, NULL );
    is_running = false;
}

void event_thread_t::EventMouse( vlc_mouse_t const* new_state, void* userdata )
{
    ESInfo* info = static_cast<ESInfo*>( userdata );
    vlc_mutex_locker lock_guard( &info->owner.lock );

    if( !new_state )
        return vlc_mouse_Init( &info->mouse_state );

    info->owner.pending_events.push_back( EventInfo( info, info->mouse_state, *new_state ) );

    vlc_cond_signal( &info->owner.wait );
    info->mouse_state = *new_state;
}

int event_thread_t::EventKey( vlc_object_t *p_this, char const *, vlc_value_t, vlc_value_t newval, void *p_data )
{
    event_thread_t* owner = static_cast<event_thread_t*>( p_data );
    vlc_mutex_locker lock_guard( &owner->lock );

    owner->pending_events.push_back( EventInfo( static_cast<vlc_action_id_t>( newval.i_int ) ) );

    vlc_cond_signal( &owner->wait );
    msg_Dbg( p_this, "Event Key");

    return VLC_SUCCESS;
}

void event_thread_t::EventThread()
{
    vlc_object_t *vlc = VLC_OBJECT(vlc_object_instance(p_demux));
    int canc = vlc_savecancel ();

    
    var_AddCallback( vlc, "key-action", EventKey, this );

    for( vlc_mutex_locker guard( &lock );; )
    {
        while( !b_abort && pending_events.empty() )
            vlc_cond_wait( &wait, &lock );

        if( b_abort )
            break;

        while( !pending_events.empty() )
        {
            EventInfo const& ev = pending_events.front();

            switch( ev.type )
            {
                case EventInfo::ESMouseEvent:
                    HandleMouseEvent( ev );
                    break;

                case EventInfo::ActionEvent:
                    HandleKeyEvent( ev );
                    break;
            }

            pending_events.pop_front();
        }
    }

    var_DelCallback( vlc, "key-action", EventKey, this );
    vlc_restorecancel (canc);
}

void *event_thread_t::EventThread(void *data)
{
    static_cast<event_thread_t*>(data)->EventThread();
    return NULL;
}

void event_thread_t::ProcessNavAction( uint16 button, pci_t* pci )
{
    demux_sys_t* p_sys = (demux_sys_t*)p_demux->p_sys;

    if( button <= 0 || button > pci->hli.hl_gi.btn_ns )
        return;

    p_sys->dvd_interpretor.SetSPRM( 0x88, button );
    btni_t button_ptr = pci->hli.btnit[button-1];
    if ( button_ptr.auto_action_mode )
    {
        vlc_mutex_unlock( &lock );
        vlc_mutex_lock( &p_sys->lock_demuxer );

        
        p_sys->dvd_interpretor.Interpret( button_ptr.cmd.bytes, 8 );

        vlc_mutex_unlock( &p_sys->lock_demuxer );
        vlc_mutex_lock( &lock );
    }
}

void event_thread_t::HandleKeyEvent( EventInfo const& ev )
{
    msg_Dbg( p_demux, "Handle Key Event");

    demux_sys_t* p_sys = (demux_sys_t*)p_demux->p_sys;
    pci_t *pci = &pci_packet;

    uint16 i_curr_button = p_sys->dvd_interpretor.GetSPRM( 0x88 );

    if( i_curr_button <= 0 || i_curr_button > pci->hli.hl_gi.btn_ns )
        return;

    btni_t button_ptr = pci->hli.btnit[i_curr_button-1];

    switch( ev.action.id )
    {
    case ACTIONID_NAV_LEFT: return ProcessNavAction( button_ptr.left, pci );
    case ACTIONID_NAV_RIGHT: return ProcessNavAction( button_ptr.right, pci );
    case ACTIONID_NAV_UP: return ProcessNavAction( button_ptr.up, pci );
    case ACTIONID_NAV_DOWN: return ProcessNavAction( button_ptr.down, pci );
    case ACTIONID_NAV_ACTIVATE:
        {
            vlc_mutex_unlock( &lock );
            vlc_mutex_lock( &p_sys->lock_demuxer );

            
            p_sys->dvd_interpretor.Interpret( button_ptr.cmd.bytes, 8 );

            vlc_mutex_unlock( &p_sys->lock_demuxer );
            vlc_mutex_lock( &lock );
        }
        break;
    default:
        break;
    }
}

void event_thread_t::HandleMouseEvent( EventInfo const& event )
{
    demux_sys_t* p_sys = (demux_sys_t*)p_demux->p_sys;
    int x = event.mouse.state_new.i_x;
    int y = event.mouse.state_new.i_y;

    pci_t *pci = &pci_packet;

    if( vlc_mouse_HasPressed( &event.mouse.state_old, &event.mouse.state_new, MOUSE_BUTTON_LEFT ) )
    {
        int32_t button;
        int32_t best,dist,d;
        int32_t mx,my,dx,dy;

        msg_Dbg( p_demux, "Handle Mouse Event: Mouse clicked x(%d)*y(%d)", x, y);

        
        best = 0;
        dist = 0x08000000; 
        for(button = 1; button <= pci->hli.hl_gi.btn_ns; button++)
        {
            btni_t *button_ptr = &(pci->hli.btnit[button-1]);

            if(((unsigned)x >= button_ptr->x_start)
             && ((unsigned)x <= button_ptr->x_end)
             && ((unsigned)y >= button_ptr->y_start)
             && ((unsigned)y <= button_ptr->y_end))
            {
                mx = (button_ptr->x_start + button_ptr->x_end)/2;
                my = (button_ptr->y_start + button_ptr->y_end)/2;
                dx = mx - x;
                dy = my - y;
                d = (dx*dx) + (dy*dy);
                
                if(d < dist) {
                    dist = d;
                    best = button;
                }
            }
        }

        if ( best != 0)
        {
            btni_t button_ptr = pci->hli.btnit[best-1];
            uint16 i_curr_button = p_sys->dvd_interpretor.GetSPRM( 0x88 );

            msg_Dbg( &p_sys->demuxer, "Clicked button %d", best );
            vlc_mutex_unlock( &lock );
            vlc_mutex_lock( &p_sys->lock_demuxer );

            
            p_sys->dvd_interpretor.SetSPRM( 0x88, best );
            p_sys->dvd_interpretor.Interpret( button_ptr.cmd.bytes, 8 );

            msg_Dbg( &p_sys->demuxer, "Processed button %d", best );

            
            if ( best != i_curr_button )
            {
                
                vlc_spu_highlight_t spu_hl = vlc_spu_highlight_t();

                spu_hl.x_start = (int)button_ptr.x_start;
                spu_hl.y_start = (int)button_ptr.y_start;

                spu_hl.x_end = (int)button_ptr.x_end;
                spu_hl.y_end = (int)button_ptr.y_end;

                uint32_t i_palette;

                if(button_ptr.btn_coln != 0) {
                    i_palette = pci->hli.btn_colit.btn_coli[button_ptr.btn_coln-1][1];
                } else {
                    i_palette = 0;
                }

                for( int i = 0; i < 4; i++ )
                {
                    uint32_t i_yuv = 0xFF;
                    uint8_t i_alpha = (i_palette>>(i*4))&0x0f;
                    i_alpha = i_alpha == 0xf ? 0xff : i_alpha << 4;

                    spu_hl.palette.palette[i][0] = (i_yuv >> 16) & 0xff;
                    spu_hl.palette.palette[i][1] = (i_yuv >> 0) & 0xff;
                    spu_hl.palette.palette[i][2] = (i_yuv >> 8) & 0xff;
                    spu_hl.palette.palette[i][3] = i_alpha;
                }

                
                for( es_list_t::iterator it = es_list.begin(); it != es_list.end(); ++it )
                {
                    if( it->category != SPU_ES )
                        continue;

                    es_out_Control( p_demux->out, ES_OUT_SPU_SET_HIGHLIGHT, it->es, &spu_hl );
                }
            }
            vlc_mutex_unlock( &p_sys->lock_demuxer );
            vlc_mutex_lock( &lock );
        }
    }
    else if( vlc_mouse_HasMoved( &event.mouse.state_old, &event.mouse.state_new ) )
    {

    }
}

bool event_thread_t::AddES( es_out_id_t* es, int category )
{
    vlc_mutex_locker lock_guard( &lock );

    es_list.push_front( ESInfo( es, category, *this ) );
    es_list_t::iterator info = es_list.begin();

    if( category == VIDEO_ES )
    {
        if( es_out_Control( p_demux->out, ES_OUT_VOUT_SET_MOUSE_EVENT, es, EventMouse, static_cast<void*>( &*info ) ) )
        {
            msg_Warn( p_demux, "Unable to subscribe to mouse events" );
            es_list.erase( info );
            return false;
        }
    }
    return true;
}

void event_thread_t::DelES( es_out_id_t* es )
{
    vlc_mutex_locker lock_guard( &lock );
    es_list.erase( std::find( es_list.begin(), es_list.end(), es ) );
}

} 

