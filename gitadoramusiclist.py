# vim: set fileencoding=utf-8
import xml.etree.ElementTree as ET

def import_gitadora_musiclist(xmlfile: str) -> None:
    with open(xmlfile, 'rb') as xmlhandle:
        xmldata = xmlhandle.read().decode('utf-8')
        root = ET.fromstring(xmldata)
    final_music_list = [] #output_list
    for music_entry in root.findall('mdb_data'):
        if music_entry.find("xg_diff_list").text not in ['0 0 0 0 0 0 0 0 0 0 0 0 0 0 0', '1 2 3 4 5 1 2 3 4 5 0 1 2 3 4']:
            #musicid, is_hot, data_ver, difficulty
            musicid = int(music_entry.find('music_id').text) #musicid
            is_hot = 0 #is_hot
            data_ver = int(music_entry.find('data_ver').text) #data_ver
            difficulties_list = music_entry.find('xg_diff_list').text
            difficulties_space_split_list = difficulties_list.split(' ')
            difficulties = list(map(eval, difficulties_space_split_list)) #difficulties list
            for change_item in range(6,10):
                difficulties[change_item], difficulties[change_item + 5] = difficulties[change_item + 5], difficulties[change_item]
            #fuzzup
            #is_hot_list = [413,516,532,608,705,1110,1114,1130,1133,1462,1508,1547,1623,2531,2539,2590, 2591, 2592, 2593, 2594, 2595, 2596, 2597, 2598, 2599, 2600, 2601, 2602, 2603, 2604, 2605, 2606, 2607, 2608, 2609, 2610, 2611, 2612, 2613, 2614, 2615, 2616, 2617, 2618, 2619, 2620, 2621, 2622, 2623, 2624, 2625, 2626, 2627, 2628, 2629, 2630, 2631, 2632, 2633, 2634, 2635, 2636, 2637, 2638, 2639, 2640, 2641, 2642, 2643, 2644, 2645, 2646, 2647, 2648, 2649, 2650, 2651, 2652, 2653, 2654, 2655, 2656, 2657, 2658, 2659, 2660, 2661, 2662, 2663, 2664, 2665, 2666, 2667, 2668, 2669, 2670, 2678,2679,2680,2695,2697,2698,2699,2711]
            #<contain_stat __type="u8" __count="2">1 1</contain_stat>
            contain_stat = music_entry.find('contain_stat').text
            if contain_stat == '1 1' or contain_stat == '3 3': #grab the hot music without the hot musiclists.
                is_hot = 1
            if contain_stat != '0 0' and contain_stat != '1 1' and contain_stat != '2 2' and contain_stat != '3 3': #click else musiclists.
                print(musicid)
            music_item_list = (musicid,is_hot,data_ver,difficulties)
            final_music_list.append(
                (musicid,
                is_hot,
                data_ver,
                difficulties
                ),
            )
            with open('test.txt','a+') as f:
                f.write(str(music_item_list))
                f.write(", ")
                f.write("\n")
        else:
            continue

if __name__ == "__main__":
    import_gitadora_musiclist(xmlfile='mdb_fz.xml')