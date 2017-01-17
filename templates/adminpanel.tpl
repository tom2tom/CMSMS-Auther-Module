{if !empty($message)}<p>{$message}</p><br />{/if}
{$tab_headers}

{$start_items_tab}
{$startform1}
{if ($icount > 0)}
<div style="overflow:auto;">
 <table id="itemstable" class="leftwards pagetable">
  <thead><tr>
   <th>{$title_name}</th>
   <th>{$title_alias}</th>
   <th>{$title_id}</th>
   <th class="pageicon"></th>
   <th class="pageicon"></th>
{if $mod} <th class="pageicon"></th>
   <th class="pageicon"></th>
   <th class="checkbox"></th>{/if}
  </tr></thead>
  <tbody>
 {foreach from=$items item=entry} {cycle values='row1,row2' assign='rowclass'}
  <tr class="{$rowclass}" onmouseover="this.className='{$rowclass}hover';" onmouseout="this.className='{$rowclass}';">
   <td>{$entry->name}</td>
   <td>{$entry->alias}</td>
   <td>{$entry->id}</td>
   <td>{$entry->users}</td>
   <td>{$entry->see}</td>
{if $mod} <td>{$entry->edit}</td>
   <td class="linkdel">{$entry->del}</td>
   <td class="checkbox">{$entry->sel}</td>{/if}
  </tr>
 {/foreach}
  </tbody>
 </table>
</div>
{else}
 <p class="pageinput">{$noitems}</p>
{/if}
{if $mod}<div id="itemacts" class="pageoptions" style="margin-top:1em;">
{$iconlinkadd} {$textlinkadd}{if ($icount > 0)}span style="margin-left:12em;"{$delbtn}</span>{/if}
</div>{/if}
{$endform}
{$end_tab}
{if $set}

{$start_settings_tab}
{$startform2}
<div class="pageinput" style="overflow:auto;">
<p>{$compulsory}</p>
{foreach from=$settings item=entry}
 <p class="pagetext" style="margin-left:0;">{$entry->title}:{if !empty($entry->must)} *{/if}</p>
 <div>{$entry->input}</div>
 {if !empty($entry->help)}<p>{$entry->help}</p>{/if}
{/foreach}
</div>
<div class="pageinput pageoptions" style="margin-top:1em;">
{$submit} {$cancel}
</div>
{$endform}
{$end_tab}
{/if}

{$tab_footers}
