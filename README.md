The sunburst_decode and sunburst_stage2 custom lookups decode Sunburst encoded DNS requests.

### Lookups

The special lookups expect specific data that has already been cleaned and/or aggregated.

Because some data spans multiple requests, the data should be aggregated as much as possible beforehand to have the best results.

This increases the amount of SPL required to decode the DGA queries, but it provides more flexibility.

```
query="*.appsync-api.*.avsvmcloud.com"
| lookup sunburst_decode encoded AS query OUTPUT decoded
| makemv delim=";" decoded 
| eval guid = mvindex(decoded, 0) 
| eval decoded_domain = case(mvcount(decoded)=4, mvindex(decoded, 1)) 
| eval decode_method = case(mvcount(decoded)=4, mvindex(decoded, 2)) 
| eval decode_index = case(mvcount(decoded)=4, mvindex(decoded, 3))
| eval stage2_time = case(mvcount(decoded)=3, mvindex(decoded, 1))
| eval stage2_info = case(mvcount(decoded)=3, mvindex(decoded, 2))
| makemv delim="|" stage2_info
| fieldformat stage2_time = strftime(stage2_time, "%c")
| eval encoded_values = case(isnotnull(decode_index), substr(mvindex(split(encoded, "."), 0), 17, 64)) 
| eventstats values(encoded_values) as encoded_values by guid
| eval subs_encoded = case(NOT match(encoded_values, "^00"), encoded_values)
| eval base32_encoded = case(match(encoded_values, "^00"), encoded_values)
| mvcombine delim="|" base32_encoded
| nomv base32_encoded
| lookup sunburst_b32_decode_list encoded AS base32_encoded OUTPUT decoded AS b32_decoded
| lookup sunburst_subs_decode_list encoded AS subs_encoded OUTPUT decoded AS subs_decoded
| makemv delim=";" decoded_b32
| makemv delim=";" subs_decoded
```

#### Support

This is an open source project, no support provided, public repository available.

https://github.com/malvidin/sunburst_decode

*The modified splunklib will be removed when the related issue with leading spaces is resolved.*

### History

**v1.0**
- Initial release
